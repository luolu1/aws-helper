"""持久层测试：加密、幂等、级联删除。"""

from __future__ import annotations

import pytest

from aws_helper.store import Store


def test_secret_key_is_encrypted_at_rest(store):
    """落盘的任何文件里都不能出现明文 Secret Key。

    SQLite 处于 WAL 模式，新写入先进 .db-wal，所以要扫整个数据目录，
    只看主库文件会漏检。
    """
    store.add_account("acct", "AKIAEXAMPLE", "SUPERSECRETVALUE", "us-east-1")

    on_disk = [p for p in store.dir.iterdir() if p.is_file()]
    assert on_disk
    for path in on_disk:
        assert b"SUPERSECRETVALUE" not in path.read_bytes(), f"明文泄漏于 {path.name}"

    # Access Key 不是机密，按设计明文存储以便展示掩码
    assert any(b"AKIAEXAMPLE" in p.read_bytes() for p in on_disk)


def test_credentials_roundtrip(store):
    aid = store.add_account("acct", "AKIA123", "sk-value", "ap-northeast-1")
    creds = store.credentials(aid)
    assert creds.access_key == "AKIA123"
    assert creds.secret_key == "sk-value"
    assert creds.region == "ap-northeast-1"


def test_credentials_region_override(store):
    aid = store.add_account("acct", "AKIA123", "sk", "us-east-1")
    assert store.credentials(aid, "eu-west-1").region == "eu-west-1"


def test_account_masking(store):
    aid = store.add_account("acct", "AKIAIOSFODNN7EXAMPLE", "sk", "us-east-1")
    assert store.get_account(aid).masked() == "AKIA********MPLE"


def test_duplicate_label_rejected(store):
    store.add_account("same", "AKIA1", "sk", "us-east-1")
    with pytest.raises(Exception):
        store.add_account("same", "AKIA2", "sk", "us-east-1")


def test_missing_account_raises(store):
    with pytest.raises(LookupError):
        store.credentials(9999)


def test_script_upsert_by_name(store):
    first = store.save_script("tpl", "echo v1", ["curl"])
    second = store.save_script("tpl", "echo v2", ["vim"])
    assert first == second
    scripts = store.list_scripts()
    assert len(scripts) == 1
    assert scripts[0]["body"] == "echo v2"
    assert scripts[0]["packages"] == ["vim"]


def test_keypair_encrypted_and_retrievable(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    store.save_keypair(aid, "us-east-1", "k1", "-----BEGIN PRIVATE KEY-----xyz")
    assert store.get_private_key(aid, "us-east-1", "k1").endswith("xyz")
    assert b"BEGIN PRIVATE KEY" not in store.db_path.read_bytes()


def test_keypair_missing_returns_none(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    assert store.get_private_key(aid, "us-east-1", "nope") is None


def test_ip_rule_upsert_is_idempotent(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    kw = dict(
        account_id=aid,
        region="us-east-1",
        instance_id="i-1",
        enabled=1,
        strategy="eip",
        check_mode="tcp",
        check_port=22,
        interval_sec=300,
        fail_threshold=3,
        allow_cidrs=["1.0.0.0/8"],
        deny_cidrs=[],
        max_attempts=3,
    )
    r1 = store.save_ip_rule(**kw)
    r2 = store.save_ip_rule(**{**kw, "check_port": 443})
    assert r1 == r2
    rules = store.list_ip_rules()
    assert len(rules) == 1
    assert rules[0]["check_port"] == 443
    assert rules[0]["allow_cidrs"] == ["1.0.0.0/8"]


def test_rule_state_updates(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    rid = store.save_ip_rule(
        account_id=aid, region="us-east-1", instance_id="i-1", enabled=1
    )
    store.update_rule_state(rid, fail_count=2, last_check=111)
    rule = store.list_ip_rules()[0]
    assert rule["fail_count"] == 2
    assert rule["last_check"] == 111


def test_enabled_only_filter(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    store.save_ip_rule(account_id=aid, region="us-east-1", instance_id="i-on", enabled=1)
    store.save_ip_rule(account_id=aid, region="us-east-1", instance_id="i-off", enabled=0)
    assert len(store.list_ip_rules()) == 2
    active = store.list_ip_rules(enabled_only=True)
    assert len(active) == 1
    assert active[0]["instance_id"] == "i-on"


def test_delete_account_cascades(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    store.save_keypair(aid, "us-east-1", "k1", "priv")
    store.save_ip_rule(account_id=aid, region="us-east-1", instance_id="i-1", enabled=1)

    store.delete_account(aid)
    assert store.list_keypairs() == []
    assert store.list_ip_rules() == []


def test_logs_ordering_and_limit(store):
    for i in range(5):
        store.log("kind", f"t{i}", True, f"detail {i}")
    logs = store.list_logs(limit=3)
    assert len(logs) == 3
    assert logs[0]["target"] == "t4"


def test_log_failure_flag(store):
    store.log("launch", "i-1", False, "boom")
    assert store.list_logs()[0]["ok"] == 0


def test_reopen_same_dir_keeps_data(tmp_path):
    """重启进程后凭据仍能解密 —— secret.key 落盘生效。"""
    s1 = Store(tmp_path / "d")
    aid = s1.add_account("a", "AKIA1", "secret-value", "us-east-1")
    s1.close()

    s2 = Store(tmp_path / "d")
    assert s2.credentials(aid).secret_key == "secret-value"
    s2.close()
