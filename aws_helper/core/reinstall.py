"""重装系统：换掉实例的根卷。

用 EC2 的 ReplaceRootVolume —— 这是 AWS 上最贴近"重装系统"的原语：

  保留：实例 ID、私有 IP、公网/弹性 IP、安全组、网卡、挂载的数据卷、
        IAM 实例配置文件、user-data、实例类型
  清空：根卷上的一切（系统、已装软件、/root 与 /home、配置）

对比另外两条路：
- 终止后重开：实例 ID 变、动态公网 IP 变、安全组要重建，等于换了台机器
- 快照回滚：只能回到某个时间点，装不了别的系统

不传 ImageId 就用实例原本的 AMI 重铺（相当于恢复出厂）；传了就换成别的系统 ——
但架构必须和实例匹配，x86 机器铺 ARM 镜像会得到一台起不来的实例。
"""

from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from . import aws

ProgressFn = Callable[[str], None]


def _noop(_: str) -> None:
    return None


# 换根卷要建卷、等实例停、挂新卷、再起来，实测 3-5 分钟。
# 给到 15 分钟：大磁盘和繁忙区域会更慢。
_TASK_TIMEOUT = 900
_POLL_INTERVAL = 10

_TERMINAL = ("succeeded", "failed", "failed-detached")

# 重装后 SSM Agent 要等新系统起来才重新注册，实测 1-3 分钟。
_AGENT_WAIT = 300
_AGENT_POLL = 15


class ReinstallError(RuntimeError):
    """重装失败。"""


_SSH_USER_BY_KEYWORD: tuple[tuple[str, str], ...] = (
    ("ubuntu", "ubuntu"),
    ("debian", "admin"),
    ("amzn", "ec2-user"),
    ("amazon", "ec2-user"),
    ("al2023", "ec2-user"),
    ("rhel", "ec2-user"),
    ("suse", "ec2-user"),
    ("sles", "ec2-user"),
    ("fedora", "fedora"),
    ("centos", "centos"),
    ("rocky", "rocky"),
    ("alma", "ec2-user"),
    ("windows", "Administrator"),
)


def _guess_ssh_user(image_name: str, platform: str) -> str:
    """从镜像名猜默认登录用户。

    重装后连不上最常见的原因就是用户名换了（Ubuntu 是 ubuntu、Debian 是 admin、
    AL2023 是 ec2-user）。恢复出厂时我们没有 image_key，只能从 AMI 名字推断。
    猜不出来时返回空串，页面提示用户自己确认，而不是给一个错的用户名。
    """
    if platform.lower() == "windows":
        return "Administrator"
    lowered = image_name.lower()
    for keyword, user in _SSH_USER_BY_KEYWORD:
        if keyword in lowered:
            return user
    return ""


def preflight(
    creds: aws.Credentials,
    region: str,
    instance_id: str,
    image_key: str = "",
    image_id: str = "",
) -> dict[str, Any]:
    """重装前的前置校验。

    这些条件不满足时 AWS 的报错很难懂（比如架构不匹配只回一句
    InvalidParameterValue），所以在这里一次性查清楚并给人话。
    """
    session = aws.ec2(creds, region)
    try:
        resp = session.describe_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        raise ReinstallError(f"查询实例失败: {exc}") from exc

    reservations = resp.get("Reservations") or []
    instances = reservations[0].get("Instances") if reservations else []
    if not instances:
        raise ReinstallError(f"找不到实例 {instance_id}")

    info = instances[0]
    state = (info.get("State") or {}).get("Name", "")
    arch = info.get("Architecture", "")
    root_type = info.get("RootDeviceType", "")

    problems: list[str] = []
    if state == "terminated":
        problems.append("实例已终止，无法重装")
    if root_type != "ebs":
        # instance-store 的根卷是临时盘，根本没有卷可以替换
        problems.append(f"根设备类型是 {root_type}，只有 EBS 根卷能换（instance-store 不行）")

    target_image = image_id.strip()
    target_label = ""
    if not target_image and image_key:
        try:
            target_image = aws.resolve_ami(session, image_key, creds, region)
        except LookupError as exc:
            problems.append(str(exc))
        except ClientError as exc:
            problems.append(f"解析镜像 {image_key} 失败: {exc}")
        spec = aws.IMAGES.get(image_key)
        target_label = spec.label if spec else image_key

    image_arch = ""
    image_name = ""
    image_platform = ""
    if target_image and not problems:
        try:
            images = session.describe_images(ImageIds=[target_image]).get("Images") or []
        except ClientError as exc:
            problems.append(f"查询镜像 {target_image} 失败: {exc}")
            images = []
        if images:
            image_arch = images[0].get("Architecture", "")
            image_name = images[0].get("Name", "")
            image_platform = images[0].get("Platform", "")
            # 架构不匹配是最容易踩的坑：换完实例起不来，且没有明显报错
            if image_arch and arch and image_arch != arch:
                problems.append(
                    f"镜像架构 {image_arch} 与实例架构 {arch} 不匹配 —— "
                    f"换上去实例起不来。请选 {arch} 的镜像，"
                    f"或者先换实例类型"
                )
        elif not problems:
            problems.append(f"镜像 {target_image} 不存在或不可用")

    # 换系统后登录用户名会变（Ubuntu 是 ubuntu、Debian 是 admin、
    # AL2023 是 ec2-user），这是重装后最容易卡住人的地方。
    # 选了内置镜像就用它声明的用户，否则从 AMI 名字猜；恢复出厂时查原镜像。
    spec = aws.IMAGES.get(image_key) if image_key else None
    if spec is not None:
        ssh_user = spec.ssh_user
        os_family = spec.os_family
    else:
        if not image_name and not problems:
            probe = target_image or info.get("ImageId", "")
            try:
                found = session.describe_images(ImageIds=[probe]).get("Images") or []
            except ClientError:
                found = []
            if found:
                image_name = found[0].get("Name", "")
                image_platform = found[0].get("Platform", "")
        ssh_user = _guess_ssh_user(image_name, image_platform)
        os_family = "windows" if image_platform.lower() == "windows" else "linux"

    return {
        "ok": not problems,
        "instance_id": instance_id,
        "state": state,
        "architecture": arch,
        "root_device_type": root_type,
        "root_device_name": info.get("RootDeviceName", ""),
        "current_image_id": info.get("ImageId", ""),
        "target_image_id": target_image,
        "target_image_label": target_label,
        "target_image_arch": image_arch,
        "private_ip": info.get("PrivateIpAddress", ""),
        "public_ip": info.get("PublicIpAddress", ""),
        # 换根卷不影响实例的 KeyName 属性，新根卷的 cloud-init 照旧从 IMDS
        # 取同一个公钥，所以原私钥继续可用，无需重新生成密钥对。
        "key_name": info.get("KeyName", ""),
        "ssh_user": ssh_user,
        "os_family": os_family,
        # 数据卷会原样保留，页面上要说清楚，否则用户不敢点
        "extra_volumes": [
            m.get("DeviceName", "")
            for m in (info.get("BlockDeviceMappings") or [])
            if m.get("DeviceName") != info.get("RootDeviceName")
        ],
        "problems": problems,
    }


def _wait_task(
    session: Any, task_id: str, progress: ProgressFn, timeout: float | None = None
) -> dict[str, Any]:
    # 默认值在调用时才读模块变量。写成 timeout=_TASK_TIMEOUT 的话默认值在
    # def 执行时就固定了，测试改 _TASK_TIMEOUT 完全不生效，超时用例会真等 15 分钟。
    if timeout is None:
        timeout = _TASK_TIMEOUT
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        try:
            resp = session.describe_replace_root_volume_tasks(
                ReplaceRootVolumeTaskIds=[task_id]
            )
        except ClientError as exc:
            raise ReinstallError(f"查询重装任务失败: {exc}") from exc

        tasks = resp.get("ReplaceRootVolumeTasks") or []
        if not tasks:
            raise ReinstallError(f"重装任务 {task_id} 不存在")

        last = tasks[0]
        state = last.get("TaskState", "")
        progress(f"重装状态 {state}")
        if state in _TERMINAL:
            return last
        time.sleep(_POLL_INTERVAL)

    raise ReinstallError(
        f"等待重装超时（{timeout}s），最后状态 {last.get('TaskState', '未知')}。"
        f"任务仍在后台跑，可稍后在控制台查看任务 {task_id}"
    )


def _apply_new_credentials(
    creds: aws.Credentials,
    region: str,
    instance_id: str,
    login_user: str,
    password: str,
    public_key: str,
    progress: ProgressFn,
) -> dict[str, Any]:
    """重装完设置新凭据。

    只能走 SSM：user-data 只有停机才能改（停机会丢掉未绑弹性 IP 的公网地址），
    而实例的 KeyName 属性根本不可修改。SSM 是唯一既保住 IP 又能改凭据的路。

    Agent 要等新系统起来并重新注册，所以先轮询等它回来。等不到不算重装失败 ——
    根卷已经换好了，只是凭据没设上，报告里说清楚让用户手动补。
    """
    from . import respw

    deadline = time.time() + _AGENT_WAIT
    while time.time() < deadline:
        status = respw.ssm_status(creds, region, instance_id)
        if status["registered"]:
            break
        progress(f"等待 SSM Agent 回来（{status.get('ping_status') or '未注册'}）")
        time.sleep(_AGENT_POLL)
    else:
        return {
            "applied": False,
            "reason": (
                f"重装成功，但等了 {_AGENT_WAIT}s SSM Agent 仍未在新系统上注册，"
                "凭据没能设置。可稍后在实例页用「重置密码」重试"
            ),
        }

    progress("设置新的登录凭据")
    try:
        respw.reset_password(
            creds,
            region,
            instance_id,
            password=password,
            user=login_user,
            public_key=public_key,
            progress=progress,
        )
    except respw.PasswordResetError as exc:
        return {"applied": False, "reason": f"重装成功，但设置凭据失败: {exc}"}

    return {"applied": True, "reason": ""}


def reinstall(
    creds: aws.Credentials,
    region: str,
    instance_id: str,
    image_key: str = "",
    image_id: str = "",
    delete_old_volume: bool = True,
    progress: ProgressFn = _noop,
    new_password: str = "",
    new_public_key: str = "",
) -> dict[str, Any]:
    """重装系统。image_key/image_id 都不传 = 用原镜像重铺。

    默认删掉被替换的旧根卷 —— 留着会一直按 EBS 容量计费，而用户点重装
    通常就是不要那些数据了。想留证据可以传 delete_old_volume=False。
    """
    progress("检查重装前提")
    if new_public_key:
        # 必须在换根卷之前校验：卷一换就不可逆了，等设凭据时才发现公钥是废的，
        # 用户已经丢了整个根卷还登不进去。
        from . import respw

        try:
            new_public_key = respw.validate_public_key(new_public_key)
        except respw.PasswordResetError as exc:
            raise ReinstallError(str(exc)) from exc

    checks = preflight(creds, region, instance_id, image_key, image_id)
    if not checks["ok"]:
        raise ReinstallError("；".join(checks["problems"]))

    session = aws.ec2(creds, region)
    params: dict[str, Any] = {
        "InstanceId": instance_id,
        "DeleteReplacedRootVolume": bool(delete_old_volume),
    }
    # 不传 ImageId 时 AWS 用实例原本的 AMI 重铺，这正是"恢复出厂"
    if checks["target_image_id"]:
        params["ImageId"] = checks["target_image_id"]

    started = time.time()
    progress("下发重装任务")
    try:
        resp = session.create_replace_root_volume_task(**params)
    except ClientError as exc:
        raise ReinstallError(f"下发重装任务失败: {exc}") from exc

    task = resp.get("ReplaceRootVolumeTask") or {}
    task_id = task.get("ReplaceRootVolumeTaskId", "")
    if not task_id:
        raise ReinstallError("AWS 没有返回重装任务 ID")

    progress(f"任务已创建 {task_id}，实例会短暂重启")
    final = _wait_task(session, task_id, progress)
    state = final.get("TaskState", "")

    if state != "succeeded":
        hint = ""
        if state == "failed-detached":
            # 这个状态最危险：旧卷已经卸下来了，实例现在没有根卷
            hint = (
                " —— 旧根卷已卸载但新卷没挂上，实例当前没有可启动的根卷。"
                "需要在控制台手动挂一个根卷，或用快照恢复"
            )
        raise ReinstallError(f"重装失败（{state}）{hint}")

    # 重装后 IP 不变，但登录用户名可能变了，所以把连接方式一并回给页面 ——
    # 只给一句"重装完成"的话用户还得自己去查新系统的默认用户是什么。
    ssh_user = checks["ssh_user"]
    public_ip = checks["public_ip"]
    key_name = checks["key_name"]
    windows = checks["os_family"] == "windows"

    if windows:
        ssh_command = f"RDP {public_ip}:3389" if public_ip else "无公网 IP"
    elif not public_ip:
        ssh_command = "无公网 IP，需通过内网或跳板机连接"
    elif not ssh_user:
        ssh_command = f"ssh -i {key_name or '<私钥>'}.pem <登录用户>@{public_ip}"
    else:
        ssh_command = f"ssh -i {key_name or '<私钥>'}.pem {ssh_user}@{public_ip}"

    creds_applied = False
    creds_note = ""
    login_user = ""
    if new_password or new_public_key:
        login_user = "Administrator" if windows else "root"
        outcome = _apply_new_credentials(
            creds,
            region,
            instance_id,
            login_user,
            new_password,
            new_public_key,
            progress,
        )
        creds_applied = outcome["applied"]
        creds_note = outcome["reason"]
        if creds_applied and public_ip and not windows:
            if new_password:
                ssh_command = f"ssh {login_user}@{public_ip}"
            else:
                ssh_command = f"ssh -i <你的私钥> {login_user}@{public_ip}"

    return {
        "instance_id": instance_id,
        "task_id": task_id,
        "state": state,
        "image_id": final.get("ImageId") or checks["current_image_id"],
        "image_label": checks["target_image_label"],
        "deleted_old_volume": bool(delete_old_volume),
        "elapsed_sec": int(time.time() - started),
        "private_ip": checks["private_ip"],
        "public_ip": public_ip,
        "kept_volumes": checks["extra_volumes"],
        "key_name": key_name,
        "ssh_user": ssh_user,
        "os_family": checks["os_family"],
        "ssh_command": ssh_command,
        "creds_applied": creds_applied,
        "creds_note": creds_note,
        "login_user": login_user,
        "set_password": creds_applied and bool(new_password),
        "set_public_key": creds_applied and bool(new_public_key),
        # 主机密钥随根卷一起重建，老的 known_hosts 记录会导致连接被拒
        "known_hosts_hint": (
            f"ssh-keygen -R {public_ip}" if public_ip and not windows else ""
        ),
    }
