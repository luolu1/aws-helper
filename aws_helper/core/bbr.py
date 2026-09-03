"""BBR 拥塞控制的开启脚本。

BBR 是 Linux 内核自带的拥塞控制算法（4.9+ 主线），对跨境高延迟高丢包的链路
提升明显。开启只需两条 sysctl，不用装任何东西 —— 网上那些「BBR 一键脚本」
大多在帮你换内核，那是给内核太老的老系统用的。

这里只做「开启」不做「换内核」：面板开出来的镜像（Ubuntu 22/24、Debian 12、
Amazon Linux 2023）内核都在 5.10 以上，BBR 早就编译进去了。换内核要重启、
可能起不来，不该在开机脚本里悄悄干这种事。

fq 是配套的队列规则。BBR 依赖发包时机（pacing），传统 pfifo_fast 没有这个
能力，只设 congestion_control 不设 qdisc 时 BBR 的效果会打折。内核 4.20+
的 BBR 自带内部 pacing，但显式设 fq 在所有版本上都对，代价只是一行。
"""

from __future__ import annotations

SYSCTL_PATH = "/etc/sysctl.d/99-aws-helper-bbr.conf"

TEMPLATE_NAME = "BBR 加速"

# 用户在开机脚本页看到的可编辑内容。刻意保持可读 —— 这是给人改的，
# 不是内部实现。
TEMPLATE_BODY = f"""\
# 开启 BBR 拥塞控制 + fq 队列
# 对跨境高延迟链路提升明显。只改 sysctl，不换内核。

if ! grep -qw tcp_bbr /proc/modules 2>/dev/null; then
    modprobe tcp_bbr 2>/dev/null || true
fi

# 内核不支持时只跳过 BBR，不退出外层 user-data；BBR 段也会被内联到
# 用户脚本之前，exit 0 会把用户自己的脚本一并跳掉。
if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    echo "当前内核不支持 BBR（需要 4.9+），已跳过" >&2
else
    cat > {SYSCTL_PATH} <<'BBR_EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
BBR_EOF

    # 直接对这个文件生效，不用 sysctl --system：后者读不到目标文件时也返回 0，
    # 拿它的退出码做兜底判断永远不会触发。
    sysctl -p {SYSCTL_PATH} >/dev/null 2>&1 || true

    # 校验真的生效了。写进配置文件不等于当前内核接受了它。
    now=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)
    if [ "$now" = "bbr" ]; then
        echo "BBR 已开启（qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)）"
    else
        echo "BBR 开启失败，当前算法仍是 $now" >&2
    fi
fi
"""


def render() -> str:
    """返回开启 BBR 的脚本片段，可直接作为开机脚本或拼进 user-data。"""
    return TEMPLATE_BODY
