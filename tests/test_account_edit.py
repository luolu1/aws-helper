"""账号编辑与代理配置的持久层测试。"""

from __future__ import annotations

import pytest

from aws_helper.store import Store


def test_add_account_with_proxy(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1", proxy="127.0.0.1:1080")
    assert store.get_account(aid).proxy == "socks5h://127.0.0.1:1080"
    assert store.credentials(aid).proxy == "socks5h://127.0.0.1:1080"


def test_add_account_without_proxy(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    assert store.get_account(aid).proxy is None
    assert store.credentials(aid).proxy is None


def test_proxy_encrypted_at_rest(store):
    """代理里的用户名密码同样是机密，落盘任何文件都不能有明文。"""
    store.add_account(
        "a", "AKIA1", "sk", "us-east-1", proxy="socks5h://puser:ppass@9.8.7.6:1080"
    )
    for path in store.dir.iterdir():
        if path.is_file():
            raw = path.read_bytes()
            assert b"ppass" not in raw, f"代理密码明文泄漏于 {path.name}"
            assert b"9.8.7.6" not in raw, f"代理地址明文泄漏于 {path.name}"


def test_masked_proxy_hides_password(store):
    aid = store.add_account(
        "a", "AKIA1", "sk", "us-east-1", proxy="socks5h://u:secret@1.2.3.4:1080"
    )
    masked = store.get_account(aid).masked_proxy()
    assert "secret" not in masked
    assert "1.2.3.4" in masked


def test_invalid_proxy_rejected_on_add(store):
    from aws_helper.core.aws import ProxyError

    with pytest.raises(ProxyError):
        store.add_account("a", "AKIA1", "sk", "us-east-1", proxy="ftp://1.2.3.4:21")


def test_update_label_and_region(store):
    aid = store.add_account("old", "AKIA1", "sk", "us-east-1")
    store.update_account(aid, label="new", region="ap-northeast-1")
    acct = store.get_account(aid)
    assert acct.label == "new"
    assert acct.region == "ap-northeast-1"


def test_update_keeps_secret_when_omitted(store):
    """编辑时不重填 Secret 应保留原密钥。"""
    aid = store.add_account("a", "AKIA1", "original-secret", "us-east-1")
    store.update_account(aid, label="renamed")
    assert store.credentials(aid).secret_key == "original-secret"


def test_update_replaces_secret_when_given(store):
    aid = store.add_account("a", "AKIA1", "old-secret", "us-east-1")
    store.update_account(aid, secret_key="new-secret")
    assert store.credentials(aid).secret_key == "new-secret"


def test_update_adds_proxy(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    store.update_account(aid, proxy="socks5://1.2.3.4:1080")
    assert store.get_account(aid).proxy == "socks5h://1.2.3.4:1080"


def test_update_changes_proxy(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1", proxy="1.1.1.1:1080")
    store.update_account(aid, proxy="socks5h://2.2.2.2:9050")
    assert store.get_account(aid).proxy == "socks5h://2.2.2.2:9050"


def test_clear_proxy(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1", proxy="1.1.1.1:1080")
    store.update_account(aid, clear_proxy=True)
    assert store.get_account(aid).proxy is None
    assert store.credentials(aid).proxy is None


def test_update_without_clear_flag_keeps_proxy(store):
    """只改别的字段时代理不应被意外清掉。"""
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1", proxy="1.1.1.1:1080")
    store.update_account(aid, label="renamed")
    assert store.get_account(aid).proxy == "socks5h://1.1.1.1:1080"


def test_update_missing_account_raises(store):
    with pytest.raises(LookupError):
        store.update_account(9999, label="x")


def test_update_invalid_proxy_rejected(store):
    from aws_helper.core.aws import ProxyError

    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    with pytest.raises(ProxyError):
        store.update_account(aid, proxy="socks5://1.2.3.4")


def test_update_duplicate_label_rejected(store):
    store.add_account("taken", "AKIA1", "sk", "us-east-1")
    other = store.add_account("other", "AKIA2", "sk", "us-east-1")
    with pytest.raises(Exception):
        store.update_account(other, label="taken")


def test_update_noop_is_safe(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1")
    store.update_account(aid)
    assert store.get_account(aid).label == "a"


def test_credentials_region_override_keeps_proxy(store):
    aid = store.add_account("a", "AKIA1", "sk", "us-east-1", proxy="1.1.1.1:1080")
    creds = store.credentials(aid, "eu-west-1")
    assert creds.region == "eu-west-1"
    assert creds.proxy == "socks5h://1.1.1.1:1080"


def test_migration_from_legacy_sqlite_without_proxy_column(tmp_path):
    """旧 SQLite 缺 proxy_blob 列时也要能迁移，且原数据完好。

    proxy_blob 是后加的列，更早版本的库没有它 —— 迁移必须按实际存在的
    列取交集，不能假定 schema 一致。
    """
    import sqlite3
    import time

    from cryptography.fernet import Fernet

    data_dir = tmp_path / "legacy"
    data_dir.mkdir()
    key = Fernet.generate_key()
    (data_dir / "secret.key").write_bytes(key)
    blob = Fernet(key).encrypt(b"legacy-secret").decode()

    conn = sqlite3.connect(data_dir / "aws-helper.db")
    conn.executescript(
        """
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL UNIQUE,
            access_key TEXT NOT NULL,
            secret_blob TEXT NOT NULL,
            region TEXT NOT NULL DEFAULT 'us-east-1',
            note TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT INTO accounts(label,access_key,secret_blob,region,note,created_at)"
        " VALUES(?,?,?,?,?,?)",
        ("legacy", "AKIAOLD", blob, "us-east-1", "", int(time.time())),
    )
    conn.commit()
    conn.close()

    store = Store(data_dir)
    try:
        acct = store.list_accounts()[0]
        assert acct.label == "legacy"
        assert acct.proxy is None
        assert store.credentials(acct.id).secret_key == "legacy-secret"

        store.update_account(acct.id, proxy="socks5://9.9.9.9:1080")
        assert store.get_account(acct.id).proxy == "socks5h://9.9.9.9:1080"
    finally:
        store.close()
