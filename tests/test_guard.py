"""实例侧探测（agent 模式）的测试。"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from aws_helper import autoip
from aws_helper.core import guard_script as gs


# ---------- 探测目标解析 ----------


def test_default_target_when_empty():
    assert gs.parse_target("") == (gs.DEFAULT_TARGET.split(":")[0], 443)


@pytest.mark.parametrize(
    "raw,expect",
    [
        ("www.baidu.com", ("www.baidu.com", 443)),
        ("qq.com:443", ("qq.com", 443)),
        ("http://baidu.com", ("baidu.com", 80)),
        ("https://taobao.com/path", ("taobao.com", 443)),
        ("1.2.3.4:8080", ("1.2.3.4", 8080)),
        ("BAIDU.COM", ("baidu.com", 443)),
    ],
)
def test_target_forms(raw, expect):
    """用户大概率直接粘网址，报错不如兼容。"""
    assert gs.parse_target(raw) == expect


@pytest.mark.parametrize(
    "raw", ["baidu.com:99999", "baidu.com:abc", "!!!", "https://", "  "]
)
def test_bad_targets_rejected(raw):
    if raw.strip() == "":
        assert gs.parse_target(raw)[1] == 443
        return
    with pytest.raises(gs.GuardScriptError):
        gs.parse_target(raw)


# ---------- 脚本生成 ----------


def _req(**over):
    base = dict(
        instance_id="i-0abc",
        report_url="http://1.2.3.4:8766/report",
        token="tok-xyz",
        target="www.baidu.com:443",
        interval_sec=60,
        fail_threshold=3,
    )
    base.update(over)
    return gs.GuardRequest(**base)


def test_script_requires_url_and_token():
    for missing in ("report_url", "token"):
        with pytest.raises(gs.GuardScriptError):
            gs.render_script(_req(**{missing: ""}))


def test_instance_id_may_be_empty_for_launch_time_deploy():
    """开机时部署拿不到实例 ID —— user-data 在 RunInstances 之前就得定稿。

    脚本改为开机后从 IMDS 自己读，所以生成时允许留空。
    """
    script = gs.render_script(_req(instance_id=""))
    assert "GUARD_INSTANCE_ID=''" in script
    assert "169.254.169.254/latest/meta-data/instance-id" in script


def test_explicit_instance_id_wins_over_imds():
    """手工生成的脚本写死了 ID，不能被 IMDS 覆盖 —— 那台机器可能不是它。"""
    body = gs._guard_body()
    assert 'if [ -z "${GUARD_INSTANCE_ID:-}" ]; then' in body


def test_script_rejects_non_http_url():
    with pytest.raises(gs.GuardScriptError, match="http"):
        gs.render_script(_req(report_url="ftp://x/y"))


def test_interval_has_floor():
    """探测太密集没意义：换一次 IP 本身要几十秒，而且频繁连同一站点像扫描。"""
    script = gs.render_script(_req(interval_sec=1))
    assert "GUARD_INTERVAL=20" in script


@pytest.mark.parametrize(
    "token",
    ["a'b;rm -rf /", 'x"y$z', "tok`whoami`", "a b c", "plain-token-123"],
)
def test_token_survives_shell_quoting(tmp_path, token):
    """凭证进 env 文件必须正确转义。

    断言方式是**真的用 bash source 一遍**再读回来 —— 只检查有没有引号
    证明不了转义是对的，含 $ ` ; 的值靠肉眼看很容易漏。
    """
    import subprocess

    script = gs.render_script(_req(token=token))
    env_lines = []
    for line in script.split("\n"):
        if line.startswith("GUARD_") and "=" in line:
            env_lines.append(line)
    env_file = tmp_path / "guard.env"
    env_file.write_text("\n".join(env_lines) + "\n")

    out = subprocess.run(
        ["bash", "-c", f'set -e; . "{env_file}"; printf %s "$GUARD_TOKEN"'],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout == token, f"{out.stdout!r} != {token!r}"


def test_script_only_reports_on_block():
    """正常时不上报是用户明确要求的 —— 省面板开销。"""
    body = gs._guard_body()
    assert "report blocked" in body
    # 探测成功的分支里不能有 report 调用
    success_branch = body.split("if probe; then")[1].split("else")[0]
    assert "report " not in success_branch


def test_script_has_low_frequency_heartbeat():
    """完全不通信面板就分不清「一切正常」和「脚本挂了」。"""
    body = gs._guard_body()
    assert "heartbeat_every" in body
    assert "report alive" in body


def test_probe_has_timeout():
    """/dev/tcp 自己没有超时，连不上会挂到内核放弃，整个循环就卡死了。"""
    body = gs._guard_body()
    probe = body.split("probe() {")[1].split("}")[0]
    assert "timeout" in probe


def test_script_backs_off_after_reporting():
    """面板换 IP 要几十秒，这期间继续探测会立刻又达阈值、重复上报。"""
    body = gs._guard_body()
    assert "sleep 120" in body


def test_systemd_unit_restarts_always():
    script = gs.render_script(_req())
    assert "Restart=always" in script
    assert f"systemctl enable {gs.SERVICE_NAME}" in script


def test_env_file_is_600_before_write():
    """先建文件再收权限，否则凭证有一瞬间是全局可读的。"""
    script = gs.render_script(_req())
    touch_at = script.index(f"touch {gs.ENV_PATH}")
    chmod_at = script.index(f"chmod 600 {gs.ENV_PATH}")
    write_at = script.index("GUARD_TOKEN=")
    assert touch_at < chmod_at < write_at


# ---------- 面板侧处理上报 ----------


def _rule(**over):
    base = {
        "id": 7,
        "account_id": 1,
        "region": "us-east-1",
        "instance_id": "i-0abc",
        "enabled": 1,
        "strategy": "eip",
        "probe_mode": "agent",
        "allow_cidrs": [],
        "deny_cidrs": [],
        "max_attempts": 3,
        "last_change": 0,
        "agent_interval_sec": 60,
    }
    base.update(over)
    return base


def test_agent_mode_skips_panel_probe():
    """面板在海外，从海外连实例通常一直是通的，用这个信号判断被墙是错的。"""
    store = MagicMock()
    with patch.object(autoip, "probe") as p:
        out = autoip.check_rule(store, _rule())
        p.assert_not_called()
    assert out["action"] == "skip"
    store.credentials.assert_not_called()


def test_local_mode_still_probes(monkeypatch):
    store = MagicMock()
    store.list_ip_rules.return_value = []
    rule = _rule(probe_mode="local", interval_sec=0, last_check=0, check_mode="tcp",
                 check_port=22, fail_count=0, fail_threshold=3)
    with patch.object(autoip.launch, "list_instances") as li, \
            patch.object(autoip, "probe") as p:
        li.return_value = [
            {"instance_id": "i-0abc", "state": "running", "public_ip": "1.1.1.1"}
        ]
        p.return_value = autoip.ProbeResult(True, "ok")
        autoip.check_rule(store, rule)
        p.assert_called_once()


def test_heartbeat_does_not_change_ip():
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as ci:
        out = autoip.handle_agent_report(store, _rule(), "alive", "探测正常")
        ci.assert_not_called()
    assert out["action"] == "heartbeat"
    store.touch_agent.assert_called_once()
    assert store.touch_agent.call_args.kwargs.get("reported") in (None, False)


def test_blocked_report_changes_ip():
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as ci:
        ci.return_value = MagicMock(old_ip="1.1.1.1", new_ip="2.2.2.2", attempts=1)
        out = autoip.handle_agent_report(store, _rule(), "blocked", "连不上")

    assert out["action"] == "changed"
    assert out["new_ip"] == "2.2.2.2"
    store.touch_agent.assert_called_once()
    assert store.touch_agent.call_args.kwargs["reported"] is True


def test_blocked_report_respects_cooldown():
    """实例侧也会退避，但两边各有一层才拦得住重装脚本、多次部署。"""
    store = MagicMock()
    recent = int(time.time()) - 60
    with patch.object(autoip.ipchange, "change_ip") as ci:
        out = autoip.handle_agent_report(
            store, _rule(last_change=recent), "blocked", "连不上"
        )
        ci.assert_not_called()
    assert out["action"] == "cooldown"
    assert out["retry_after"] > 0


def test_disabled_rule_ignores_report():
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip") as ci:
        out = autoip.handle_agent_report(store, _rule(enabled=0), "blocked", "x")
        ci.assert_not_called()
    assert out["action"] == "skip"


def test_change_failure_is_reported_not_swallowed():
    store = MagicMock()
    with patch.object(autoip.ipchange, "change_ip", side_effect=RuntimeError("配额用尽")):
        out = autoip.handle_agent_report(store, _rule(), "blocked", "x")
    assert out["action"] == "error"
    assert "配额用尽" in out["reason"]
