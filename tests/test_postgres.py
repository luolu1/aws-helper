"""Postgres 后端专项：SQLite 迁移、并发、连接失败、schema 隔离。"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from aws_helper.auth import hash_password
from aws_helper.store import DatabaseError, Store, database_url

from .conftest import database_dsn, requires_db


def _legacy_sqlite(data_dir: Path, *, with_proxy: bool = True) -> Fernet:
    """造一份带完整数据的旧 SQLite 库，返回其加密器。"""
    data_dir.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    (data_dir / "secret.key").write_bytes(key)
    fernet = Fernet(key)
    now = int(time.time())

    proxy_col = "proxy_blob TEXT NOT NULL DEFAULT ''," if with_proxy else ""
    conn = sqlite3.connect(data_dir / "aws-helper.db")
    conn.executescript(
        f"""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL UNIQUE,
            access_key TEXT NOT NULL,
            secret_blob TEXT NOT NULL,
            region TEXT NOT NULL DEFAULT 'us-east-1',
            {proxy_col}
            note TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE, body TEXT NOT NULL,
            packages TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL
        );
        CREATE TABLE keypairs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL,
            region TEXT NOT NULL, key_name TEXT NOT NULL,
            private_key TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE TABLE ip_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL,
            region TEXT NOT NULL, instance_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            strategy TEXT NOT NULL DEFAULT 'eip',
            check_mode TEXT NOT NULL DEFAULT 'tcp',
            check_port INTEGER NOT NULL DEFAULT 22,
            interval_sec INTEGER NOT NULL DEFAULT 300,
            fail_threshold INTEGER NOT NULL DEFAULT 3,
            allow_cidrs TEXT NOT NULL DEFAULT '[]',
            deny_cidrs TEXT NOT NULL DEFAULT '[]',
            max_attempts INTEGER NOT NULL DEFAULT 3,
            fail_count INTEGER NOT NULL DEFAULT 0,
            last_check INTEGER NOT NULL DEFAULT 0,
            last_change INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
            kind TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
            ok INTEGER NOT NULL DEFAULT 1, detail TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
            ok INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT ''
        );
        """
    )

    if with_proxy:
        conn.execute(
            "INSERT INTO accounts"
            "(label,access_key,secret_blob,region,proxy_blob,note,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            ("旧账号A", "AKIAOLD1", fernet.encrypt(b"old-secret-1").decode(),
             "ap-east-1", fernet.encrypt(b"socks5h://u:p@1.2.3.4:1080").decode(),
             "迁移测试", now),
        )
        conn.execute(
            "INSERT INTO accounts"
            "(label,access_key,secret_blob,region,proxy_blob,note,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            ("旧账号B", "AKIAOLD2", fernet.encrypt(b"old-secret-2").decode(),
             "us-west-2", "", "", now),
        )
    else:
        conn.execute(
            "INSERT INTO accounts"
            "(label,access_key,secret_blob,region,note,created_at)"
            " VALUES(?,?,?,?,?,?)",
            ("旧账号A", "AKIAOLD1", fernet.encrypt(b"old-secret-1").decode(),
             "ap-east-1", "", now),
        )

    conn.execute(
        "INSERT INTO scripts(name,body,packages,created_at) VALUES(?,?,?,?)",
        ("旧模板", "echo legacy", '["curl"]', now),
    )
    conn.execute(
        "INSERT INTO keypairs(account_id,region,key_name,private_key,created_at)"
        " VALUES(?,?,?,?,?)",
        (1, "ap-east-1", "k-old",
         fernet.encrypt(b"-----BEGIN KEY-----legacy").decode(), now),
    )
    conn.execute(
        "INSERT INTO ip_rules(account_id,region,instance_id,check_port) VALUES(?,?,?,?)",
        (1, "ap-east-1", "i-legacy", 2222),
    )
    conn.execute(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
        ("admin_password_hash", hash_password("Legacy!Pass1"), now),
    )
    for i in range(5):
        conn.execute(
            "INSERT INTO logs(created_at,kind,target,ok,detail) VALUES(?,?,?,?,?)",
            (now, "launch", f"i-{i}", 1, "ok"),
        )
    conn.execute(
        "INSERT INTO login_history(created_at,ok,ip,user_agent,detail)"
        " VALUES(?,?,?,?,?)",
        (now, 1, "10.0.0.1", "Chrome", "登录成功"),
    )
    conn.commit()
    conn.close()
    return fernet


# ---------- 自动迁移 ----------


@requires_db
def test_migrates_all_tables(tmp_path):
    """旧 SQLite 的全部数据要迁到 Postgres，加密字段仍可解密。"""
    data_dir = tmp_path / "legacy"
    _legacy_sqlite(data_dir)

    store = Store(data_dir)
    try:
        accounts = {a.label: a for a in store.list_accounts()}
        assert set(accounts) == {"旧账号A", "旧账号B"}

        a = accounts["旧账号A"]
        assert a.region == "ap-east-1"
        assert store.credentials(a.id).secret_key == "old-secret-1"
        assert store.credentials(a.id).proxy == "socks5h://u:p@1.2.3.4:1080"

        assert [s["name"] for s in store.list_scripts()] == ["旧模板"]
        assert store.get_private_key(a.id, "ap-east-1", "k-old").startswith(
            "-----BEGIN KEY-----"
        )
        assert store.list_ip_rules()[0]["check_port"] == 2222
        assert store.verify_login("Legacy!Pass1"), "旧密码哈希要能继续用"
        assert len(store.list_login_history()) >= 1
        # 迁移本身也写了一条日志，所以是 5 条业务日志 + 1
        assert len(store.list_logs()) >= 5
    finally:
        store.close()


@requires_db
def test_migration_fixes_serial_sequence(tmp_path):
    """SERIAL 序列不会随手工插入的 id 前进，迁移后必须校正。

    不校正的话下一次 INSERT 会撞上已存在的 id，直接违反主键约束。
    """
    data_dir = tmp_path / "seq"
    _legacy_sqlite(data_dir)

    store = Store(data_dir)
    try:
        assert len(store.list_accounts()) == 2
        new_id = store.add_account("新账号", "AKIANEW", "new-secret", "eu-west-1")
        assert new_id > 2, f"序列未校正，新 id={new_id}"
    finally:
        store.close()


@requires_db
def test_migration_renames_legacy_file(tmp_path):
    """迁移完要给旧文件改名，否则每次启动都尝试导入。"""
    data_dir = tmp_path / "rename"
    _legacy_sqlite(data_dir)
    legacy = data_dir / "aws-helper.db"

    store = Store(data_dir)
    store.close()

    assert not legacy.exists()
    assert (data_dir / "aws-helper.db.migrated").is_file()


@requires_db
def test_migration_runs_only_once(tmp_path):
    """二次启动不能重复导入，也不能覆盖迁移后新增的数据。"""
    data_dir = tmp_path / "once"
    _legacy_sqlite(data_dir)

    first = Store(data_dir)
    first.add_account("迁移后新增", "AKIAAFTER", "s", "us-east-1")
    count = len(first.list_accounts())
    first.close()

    second = Store(data_dir)
    try:
        assert len(second.list_accounts()) == count
        assert second.verify_login("Legacy!Pass1")
    finally:
        second.close()


@requires_db
def test_migration_tolerates_missing_columns(tmp_path):
    """更早版本没有 proxy_blob 列，迁移要按列取交集而不是报错。"""
    data_dir = tmp_path / "nocol"
    _legacy_sqlite(data_dir, with_proxy=False)

    store = Store(data_dir)
    try:
        a = store.list_accounts()[0]
        assert a.label == "旧账号A"
        assert a.proxy is None
        assert store.credentials(a.id).secret_key == "old-secret-1"
    finally:
        store.close()


@requires_db
def test_no_migration_when_database_has_data(tmp_path):
    """库里已有数据时绝不能导入旧文件覆盖。"""
    data_dir = tmp_path / "guard"

    store = Store(data_dir)
    store.set_password("Existing!Pass1", validate=False)
    store.add_account("现有账号", "AKIACUR", "cur-secret", "us-east-1")
    store.close()

    # 事后放一个旧库进去，模拟用户误拷
    _legacy_sqlite(data_dir)

    store2 = Store(data_dir)
    try:
        labels = [a.label for a in store2.list_accounts()]
        assert labels == ["现有账号"], f"旧数据被误导入: {labels}"
        assert store2.verify_login("Existing!Pass1")
        assert (data_dir / "aws-helper.db").is_file(), "不该改名未导入的文件"
    finally:
        store2.close()


@requires_db
def test_no_migration_without_legacy_file(tmp_path):
    store = Store(tmp_path / "fresh")
    try:
        assert store.list_accounts() == []
        assert not store.has_password()
    finally:
        store.close()


# ---------- 连接与配置 ----------


def test_database_url_from_env(monkeypatch):
    monkeypatch.setenv("AWS_HELPER_DATABASE_URL", "postgresql://u:p@db:5432/x")
    assert database_url() == "postgresql://u:p@db:5432/x"


def test_connection_failure_gives_actionable_error(tmp_path, monkeypatch):
    """连不上库要说清怎么排查，而不是抛原始 psycopg 异常。"""
    monkeypatch.setenv(
        "AWS_HELPER_DATABASE_URL",
        "postgresql://nobody:wrong@127.0.0.1:1/nodb",
    )
    with pytest.raises(DatabaseError) as excinfo:
        Store(tmp_path / "bad")

    message = str(excinfo.value)
    assert "无法连接 Postgres" in message
    assert "AWS_HELPER_DATABASE_URL" in message


def test_connection_error_masks_password(tmp_path, monkeypatch):
    """报错里不能出现数据库密码。"""
    monkeypatch.setenv(
        "AWS_HELPER_DATABASE_URL",
        "postgresql://nobody:sup3rsecret@127.0.0.1:1/nodb",
    )
    with pytest.raises(DatabaseError) as excinfo:
        Store(tmp_path / "bad2")
    assert "sup3rsecret" not in str(excinfo.value)


@requires_db
def test_schema_isolation(tmp_path):
    """不同 schema 的数据互不可见 —— 测试隔离和多环境共库都依赖这点。"""
    dsn = database_dsn()
    a = Store(tmp_path / "sa", dsn=dsn, schema="iso_a")
    b = Store(tmp_path / "sb", dsn=dsn, schema="iso_b")
    try:
        a.add_account("只在 A", "AKIAA", "sa", "us-east-1")
        assert [x.label for x in a.list_accounts()] == ["只在 A"]
        assert b.list_accounts() == []
    finally:
        for store in (a, b):
            with store.pool.connection() as conn:
                conn.execute(f"DROP SCHEMA IF EXISTS {store.schema} CASCADE")
                conn.commit()
            store.close()


@requires_db
def test_schema_created_if_absent(tmp_path):
    store = Store(tmp_path / "auto", dsn=database_dsn(), schema="auto_created_x")
    try:
        store.add_account("x", "AKIAX", "s", "us-east-1")
        assert len(store.list_accounts()) == 1
    finally:
        with store.pool.connection() as conn:
            conn.execute("DROP SCHEMA IF EXISTS auto_created_x CASCADE")
            conn.commit()
        store.close()


# ---------- 并发 ----------


@requires_db
def test_concurrent_writes(store):
    """连接池要能承受并发写。SQLite 时代这里会 database is locked。"""
    errors: list[Exception] = []

    def worker(index: int) -> None:
        try:
            for i in range(6):
                store.log("concurrent", f"w{index}-{i}", True, "ok")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    logs = [l for l in store.list_logs(200) if l["kind"] == "concurrent"]
    assert len(logs) == 36


@requires_db
def test_concurrent_upsert_same_key(store):
    """同一 key 并发 upsert 不能违反唯一约束。"""
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            store.save_script("race", f"echo {n}", [])
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len([s for s in store.list_scripts() if s["name"] == "race"]) == 1


@requires_db
def test_concurrent_login_attempts(store):
    """失败计数并发自增不能丢数 —— 否则暴力破解锁定可被绕过。"""
    def worker() -> None:
        store.record_failure("10.1.1.1")

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    row = store._fetchone(
        "SELECT fail_count FROM login_attempts WHERE source=%s", ("10.1.1.1",)
    )
    assert row["fail_count"] == 10, f"丢失计数: {row['fail_count']}"


# ---------- 持久性 ----------


@requires_db
def test_data_survives_reconnect(tmp_path, monkeypatch):
    """关掉连接池再开，数据仍在 —— 对应服务重启场景。"""
    schema = "persist_x"
    dsn = database_dsn()

    first = Store(tmp_path / "p1", dsn=dsn, schema=schema)
    first.set_password("Persist!Pass1", validate=False)
    aid = first.add_account("持久账号", "AKIAP", "p-secret", "ap-east-1")
    first.save_keypair(aid, "ap-east-1", "kp", "PRIVATE")
    first.close()

    # 换一个数据目录也能读到库里的业务数据；加密密钥要复用
    second = Store(tmp_path / "p1", dsn=dsn, schema=schema)
    try:
        assert second.verify_login("Persist!Pass1")
        assert [a.label for a in second.list_accounts()] == ["持久账号"]
        assert second.credentials(aid).secret_key == "p-secret"
        assert second.get_private_key(aid, "ap-east-1", "kp") == "PRIVATE"
    finally:
        with second.pool.connection() as conn:
            conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
            conn.commit()
        second.close()


@requires_db
def test_monitor_survives_database_outage(store):
    """库短暂不可用时监控线程不能死掉。

    错误处理里的 store.log() 自己也要连库，会二次抛出 ——
    未捕获就会让线程永久退出，自动换 IP 之后再也不工作。
    """
    from aws_helper import autoip

    monitor = autoip.Monitor(store, tick=1)

    calls: list[int] = []

    def boom(_store, cooldown=autoip.DEFAULT_COOLDOWN):
        calls.append(1)
        raise RuntimeError("connection closed")

    original_run = autoip.run_once
    original_log = type(store).log
    autoip.run_once = boom
    # 连日志也写不进去，模拟数据库整体不可用
    type(store).log = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down"))
    try:
        monitor.start()
        time.sleep(2.5)
        assert monitor.running, "监控线程因日志写入失败而退出"
        assert len(calls) >= 2, "线程没有继续下一轮"
    finally:
        type(store).log = original_log
        autoip.run_once = original_run
        monitor.stop()


@requires_db
def test_secret_key_stays_in_data_dir(store):
    """加密密钥留在文件里，不进数据库 —— 库泄漏时凭据仍不可解。"""
    store.add_account("acct", "AKIAK", "the-secret", "us-east-1")

    assert (store.dir / "secret.key").is_file()
    row = store._fetchone(
        "SELECT COUNT(*) AS n FROM settings WHERE value LIKE %s", ("%secret.key%",)
    )
    assert row["n"] == 0


@requires_db
def test_added_columns_backfilled_on_existing_table(tmp_path):
    """升级已有库时新列必须补上。

    SCHEMA 里是 CREATE TABLE IF NOT EXISTS，对已存在的表什么都不做 ——
    老库不会自动长出 cf_account_id，新字段的读写会全部报 UndefinedColumn。
    真机上就踩到了：restart 之后 DDNS 页直接 500。
    """
    import os
    import uuid

    import psycopg

    from .conftest import database_dsn

    dsn = database_dsn()
    schema = f"upg_{uuid.uuid4().hex[:8]}"
    os.environ["AWS_HELPER_DB_SCHEMA"] = schema
    os.environ["AWS_HELPER_DATABASE_URL"] = dsn
    os.environ["AWS_HELPER_DATA"] = str(tmp_path / "upg")

    from aws_helper import store as store_mod

    # 先按"老版本"建表：故意不含 cf_account_id
    with psycopg.connect(dsn) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
        conn.execute(f"SET search_path TO {schema}")
        conn.execute(
            "CREATE TABLE ddns_rules ("
            " id SERIAL PRIMARY KEY, provider TEXT NOT NULL DEFAULT 'cloudflare',"
            " zone TEXT NOT NULL, hostname TEXT NOT NULL,"
            " token_blob TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,"
            " want_ipv4 INTEGER NOT NULL DEFAULT 1, want_ipv6 INTEGER NOT NULL DEFAULT 0,"
            " ttl INTEGER NOT NULL DEFAULT 1, proxied INTEGER NOT NULL DEFAULT 0,"
            " interval_sec INTEGER NOT NULL DEFAULT 300, note TEXT NOT NULL DEFAULT '',"
            " last_check BIGINT NOT NULL DEFAULT 0, last_ipv4 TEXT NOT NULL DEFAULT '',"
            " last_ipv6 TEXT NOT NULL DEFAULT '', last_status TEXT NOT NULL DEFAULT '',"
            " fail_count INTEGER NOT NULL DEFAULT 0, created_at BIGINT NOT NULL DEFAULT 0,"
            " UNIQUE(provider, hostname))"
        )
        conn.commit()

    try:
        s = store_mod.Store()
        rule_id = s.save_ddns_rule(
            "example.com", "h.example.com", token="tok", cf_account_id="e" * 32
        )
        assert s.ddns_rule(rule_id)["cf_account_id"] == "e" * 32
    finally:
        with psycopg.connect(dsn) as conn:
            conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
            conn.commit()
        os.environ.pop("AWS_HELPER_DB_SCHEMA", None)


@requires_db
def test_instance_creds_added_to_existing_db(tmp_path):
    """升级已有库时 instance_creds 表要自动建出来。

    这个表是新加的，老库里没有 —— CREATE TABLE IF NOT EXISTS 会建，
    但要确认它真的在 SCHEMA 里而不是只写在 Python 方法里。
    """
    import os
    import uuid

    import psycopg

    from .conftest import database_dsn

    dsn = database_dsn()
    schema = f"ic_{uuid.uuid4().hex[:8]}"
    os.environ["AWS_HELPER_DB_SCHEMA"] = schema
    os.environ["AWS_HELPER_DATABASE_URL"] = dsn
    os.environ["AWS_HELPER_DATA"] = str(tmp_path / "ic")

    from aws_helper import store as store_mod

    try:
        s = store_mod.Store()
        aid = s.add_account("t", "AKIA0000000000000000", "sec", "us-east-1")
        s.save_instance_creds(
            aid, "us-east-1", "i-001",
            auth_method="password", login_user="root", password="S3cret!Pass1",
        )
        assert s.instance_password(aid, "us-east-1", "i-001") == "S3cret!Pass1"

        # 密码必须是加密落库的，不能明文躺在表里
        with psycopg.connect(dsn) as conn:
            conn.execute(f"SET search_path TO {schema}")
            row = conn.execute(
                "SELECT password_blob FROM instance_creds WHERE instance_id='i-001'"
            ).fetchone()
        assert row and "S3cret!Pass1" not in str(row[0]), "密码明文落库了"
    finally:
        with psycopg.connect(dsn) as conn:
            conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
            conn.commit()
        os.environ.pop("AWS_HELPER_DB_SCHEMA", None)


@requires_db
def test_instance_creds_removed_with_account(store):
    """删账号要连带删掉它下面所有实例的凭据（外键 CASCADE）。"""
    aid = store.add_account("t", "AKIA0000000000000000", "sec", "us-east-1")
    store.save_instance_creds(
        aid, "us-east-1", "i-cascade",
        auth_method="password", login_user="root", password="S3cret!Pass1",
    )
    assert store.list_instance_creds(aid, "us-east-1")

    store.delete_account(aid)
    assert store.list_instance_creds(aid, "us-east-1") == []
