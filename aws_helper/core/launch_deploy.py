"""开机时顺带部署 autoip 探测器和 DDNS 更新器。

创建实例时勾选这两项，面板把对应的一键脚本内联进 cloud-init，开机自动装好。
比事后手工登录跑脚本少一步，也避免了「机器开好了但忘了装」。

有个顺序问题要解决：user-data 在 RunInstances 之前就得定稿，那时实例 ID
还不存在。所以 autoip 的凭证按**这一批**签发，实例 ID 由脚本开机后从 IMDS
自己读，上报时带上，面板按 (凭证, 实例 ID) 定位规则。

代价说清楚：同一批实例共用一个凭证，其中一台被入侵后可以冒充同批的另一台
触发换 IP。跨批次和跨账号都拦得住，批内拦不住 —— 要批内隔离就得给每台
不同的 user-data，而 RunInstances 一次只接受一份。
"""

from __future__ import annotations

from dataclasses import dataclass

from . import ddns_script, guard_script


class DeployError(ValueError):
    """开机附带部署的参数不合法。"""


@dataclass(frozen=True, slots=True)
class AutoipDeploy:
    """开机时部署 autoip 探测器的配置。"""

    report_url: str
    token: str
    target: str = guard_script.DEFAULT_TARGET
    interval_sec: int = 60
    fail_threshold: int = 3
    strategy: str = "eip"


@dataclass(frozen=True, slots=True)
class DdnsDeploy:
    """开机时部署 DDNS 更新器的配置。"""

    zone: str
    hostname: str
    token: str
    cf_account_id: str = ""
    want_ipv4: bool = True
    want_ipv6: bool = False
    proxied: bool = False
    interval_sec: int = 300


def parse_autoip(raw: dict[str, object], report_url: str, token: str) -> AutoipDeploy:
    """从表单字段解析 autoip 部署配置。"""
    strategy = str(raw.get("strategy") or "eip")
    if strategy not in ("eip", "dynamic"):
        raise DeployError(f"未知的换 IP 方式: {strategy}")
    return AutoipDeploy(
        report_url=report_url,
        token=token,
        target=str(raw.get("target") or "").strip() or guard_script.DEFAULT_TARGET,
        interval_sec=int(raw.get("interval_sec") or 60),
        fail_threshold=int(raw.get("fail_threshold") or 3),
        strategy=strategy,
    )


def parse_ddns(raw: dict[str, object], count: int) -> DdnsDeploy:
    """从表单字段解析 DDNS 部署配置。

    count > 1 直接拒绝：一批实例共用一份 user-data，也就共用同一个主机名，
    开起来会互相把 DNS 记录改成自己的 IP，最后只有一台能被解析到。
    """
    if count > 1:
        raise DeployError(
            f"DDNS 一次只能给 1 台实例部署（当前 {count} 台）—— "
            "同批实例共用一份 user-data，会抢同一个主机名"
        )
    return DdnsDeploy(
        zone=str(raw.get("zone") or "").strip(),
        hostname=str(raw.get("hostname") or "").strip(),
        token=str(raw.get("token") or "").strip(),
        cf_account_id=str(raw.get("cf_account_id") or "").strip(),
        want_ipv4=bool(raw.get("want_ipv4", True)),
        want_ipv6=bool(raw.get("want_ipv6", False)),
        proxied=bool(raw.get("proxied", False)),
        interval_sec=int(raw.get("interval_sec") or 300),
    )


def render_autoip_block(cfg: AutoipDeploy) -> str:
    """渲染内联进 cloud-init 的 autoip 部署段。

    实例 ID 留空，由探测脚本开机后从 IMDS 自己读 —— user-data 定稿时
    实例还不存在。
    """
    script = guard_script.render_script(
        guard_script.GuardRequest(
            instance_id="",
            report_url=cfg.report_url,
            token=cfg.token,
            target=cfg.target,
            interval_sec=cfg.interval_sec,
            fail_threshold=cfg.fail_threshold,
        )
    )
    return _embed("aws-helper 自动换 IP 探测器", "autoip-deploy", script)


def render_ddns_block(cfg: DdnsDeploy) -> str:
    """渲染内联进 cloud-init 的 DDNS 部署段。"""
    script = ddns_script.render_script(
        ddns_script.ScriptRequest(
            zone=cfg.zone,
            hostname=cfg.hostname,
            token=cfg.token,
            account_id=cfg.cf_account_id,
            want_ipv4=cfg.want_ipv4,
            want_ipv6=cfg.want_ipv6,
            proxied=cfg.proxied,
            interval_sec=cfg.interval_sec,
            schedule="systemd",
        )
    )
    return _embed("aws-helper DDNS 更新器", "ddns-deploy", script)


def _embed(title: str, slug: str, script: str) -> str:
    """把一段完整的部署脚本包进 cloud-init 里执行。

    落盘再执行而不是直接内联：部署脚本里有 heredoc，套进外层 bash 会撞
    分隔符。写到 /root 下 600 权限 —— 脚本里含 API Token 和上报凭证。

    `|| true` 是刻意的：部署失败不能让整段 user-data 中止，否则用户自己写的
    脚本（永远排在最后）就不执行了。失败原因留在日志里。
    """
    path = f"/root/.aws-helper-{slug}.sh"
    log = f"/var/log/aws-helper-{slug}.log"
    marker = f"AWSHELPER_{slug.upper().replace('-', '_')}_EOF"
    return "\n".join(
        [
            f"# --- {title} ---",
            f"touch {path}",
            f"chmod 600 {path}",
            f"cat > {path} <<'{marker}'",
            script.rstrip(),
            marker,
            f"bash {path} >{log} 2>&1 || "
            f'echo "aws-helper: {title}部署失败，详见 {log}" >&2',
            "",
        ]
    )
