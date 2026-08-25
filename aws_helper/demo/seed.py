"""演示环境数据预置。

用 moto 模拟的 AWS 后端造出一批实例、脚本模板和换 IP 规则，
让演示站打开就有内容可看，不需要真实 AWS 凭据。
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from aws_helper.core import aws, launch  # noqa: E402
from aws_helper.store import Store  # noqa: E402

DEMO_ACCESS_KEY = "AKIADEMO0000EXAMPLE"
DEMO_SECRET_KEY = "demo-secret-key-not-a-real-credential"

DEMO_ACCOUNTS = [
    {
        "label": "演示账号（模拟）",
        "access_key": DEMO_ACCESS_KEY,
        "secret_key": DEMO_SECRET_KEY,
        "region": "us-east-1",
        "note": "moto 模拟后端，非真实 AWS",
        "proxy": None,
    },
    {
        "label": "演示账号-走代理",
        "access_key": "AKIADEMO0001EXAMPLE",
        "secret_key": "demo-secret-key-with-proxy",
        "region": "ap-northeast-1",
        "note": "演示按账号配置独立 SOCKS 出站代理",
        "proxy": "socks5h://demo_user:demo_pass@127.0.0.1:1080",
    },
]

SCRIPT_TEMPLATES = [
    (
        "Docker 基础环境",
        "curl -fsSL https://get.docker.com | sh\n"
        "systemctl enable --now docker\n"
        "usermod -aG docker ubuntu",
        ["curl", "git"],
    ),
    (
        "BBR 加速 + 常用工具",
        "echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf\n"
        "echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf\n"
        "sysctl -p\n"
        "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
        ["curl", "wget", "vim", "htop"],
    ),
    (
        "Nginx 站点",
        "systemctl enable --now nginx\n"
        "echo '<h1>deployed by aws-helper</h1>' > /var/www/html/index.html",
        ["nginx"],
    ),
]

DEMO_INSTANCES = [
    ("web-tokyo-01", "t3.small", [22, 80, 443], "systemctl enable --now nginx"),
    ("proxy-node-02", "t3.micro", [22, 8388], "echo proxy bootstrap"),
    ("build-runner", "t3.medium", [22], "apt-get install -y build-essential"),
]


def pick_ami(session: object) -> str:
    """从 moto 预置镜像里挑一个 Linux AMI。"""
    images = session.describe_images()["Images"]  # type: ignore[attr-defined]
    for img in images:
        name = img.get("Name", "").lower()
        if "ubuntu" in name and "hvm-ssd" in name:
            return img["ImageId"]
    for img in images:
        if "windows" not in img.get("Name", "").lower():
            return img["ImageId"]
    return images[0]["ImageId"]


def main() -> None:
    endpoint = os.environ.get("AWS_HELPER_ENDPOINT_URL")
    if not endpoint:
        print("需要设置 AWS_HELPER_ENDPOINT_URL 指向 moto 服务", file=sys.stderr)
        sys.exit(1)

    region = "us-east-1"
    store = Store()

    # 演示站要有个已知密码，否则每次启动都得去日志里翻随机密码
    demo_password = os.environ.get("AWS_HELPER_PASSWORD", "Demo!Passw0rd")
    if not store.has_password():
        store.set_password(demo_password, validate=False)
        print(f"已设置面板登录密码: {demo_password}")

    existing = {a.label for a in store.list_accounts()}
    if DEMO_ACCOUNTS[0]["label"] in existing:
        print("演示数据已存在，跳过预置")
        return

    account_id = 0
    for spec in DEMO_ACCOUNTS:
        if spec["label"] in existing:
            continue
        created = store.add_account(
            spec["label"],
            spec["access_key"],
            spec["secret_key"],
            spec["region"],
            note=spec["note"],
            proxy=spec["proxy"],
        )
        account_id = account_id or created
        tag = f"，代理 {spec['proxy']}" if spec["proxy"] else "，直连"
        print(f"已添加账号 {spec['label']} id={created}{tag}")

    for name, body, packages in SCRIPT_TEMPLATES:
        store.save_script(name, body, packages)
    print(f"已预置 {len(SCRIPT_TEMPLATES)} 个脚本模板")

    creds = aws.Credentials(DEMO_ACCESS_KEY, DEMO_SECRET_KEY, region)
    session = aws.ec2(creds, region)
    ami = pick_ami(session)
    print(f"使用镜像 {ami}")

    launched = []
    for name, itype, ports, script in DEMO_INSTANCES:
        results = launch.launch(
            creds,
            launch.LaunchRequest(
                name=name,
                region=region,
                instance_type=itype,
                image_id=ami,
                disk_size=20,
                open_ports=ports,
                script=script,
                packages=["curl"],
            ),
        )
        res = results[0]
        if res.private_key:
            store.save_keypair(account_id, region, res.key_name, res.private_key)
        store.log("launch", res.instance_id, True, f"{res.name} {itype} {res.public_ip}")
        launched.append(res)
        print(f"  开出 {res.name:14s} {res.instance_id} {res.public_ip}")

    store.save_ip_rule(
        account_id=account_id,
        region=region,
        instance_id=launched[1].instance_id,
        enabled=0,
        strategy="eip",
        check_mode="tcp",
        check_port=22,
        interval_sec=600,
        fail_threshold=3,
        allow_cidrs=[],
        deny_cidrs=["52.0.0.0/8"],
        max_attempts=3,
    )
    print(f"已为 {launched[1].name} 预置一条自动换 IP 规则（默认停用）")

    store.log("account", "演示账号（模拟）", True, "演示环境初始化完成")
    store.close()
    print("演示数据预置完成")


if __name__ == "__main__":
    main()
