"""Postgres 持久层：登录凭据、AWS 账号、脚本模板、换 IP 规则、会话、日志。

AWS Secret Key 与代理地址用 Fernet 对称加密后落库，密钥取自 AWS_HELPER_SECRET；
未设置时自动生成并存到数据目录下 secret.key（权限 0600）。
面板登录密码走单向哈希，会话令牌只存 SHA-256 摘要，两者都不可逆。

连接串取自 AWS_HELPER_DATABASE_URL。首次启动若发现库是空的、而数据目录里
还有旧版遗留的 SQLite 文件，会自动把数据迁移过来。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import psycopg
from cryptography.fernet import Fernet, InvalidToken
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import auth
from .core.aws import Credentials, mask_proxy, normalize_proxy

DEFAULT_DSN = "postgresql://awshelper@127.0.0.1:5432/awshelper"


class DatabaseError(RuntimeError):
    """数据库不可用。"""


def default_dir() -> Path:
    """数据目录，只用于放加密密钥。每次调用都重读环境变量，便于测试隔离。"""
    return Path(os.environ.get("AWS_HELPER_DATA", "~/.aws-helper")).expanduser()


def database_url() -> str:
    return os.environ.get("AWS_HELPER_DATABASE_URL", DEFAULT_DSN)


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    access_key TEXT NOT NULL,
    secret_blob TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT 'us-east-1',
    proxy_blob TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS scripts (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL,
    packages TEXT NOT NULL DEFAULT '[]',
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS keypairs (
    id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    region TEXT NOT NULL,
    key_name TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE(account_id, region, key_name)
);

CREATE TABLE IF NOT EXISTS instance_creds (
    id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    region TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    auth_method TEXT NOT NULL DEFAULT 'key',
    login_user TEXT NOT NULL DEFAULT '',
    password_blob TEXT NOT NULL DEFAULT '',
    key_name TEXT NOT NULL DEFAULT '',
    os_family TEXT NOT NULL DEFAULT 'linux',
    note TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0,
    UNIQUE(account_id, region, instance_id)
);

CREATE TABLE IF NOT EXISTS ip_rules (
    id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    region TEXT NOT NULL,
    instance_id TEXT NOT NULL,
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
    last_check BIGINT NOT NULL DEFAULT 0,
    last_change BIGINT NOT NULL DEFAULT 0,
    -- 探测只由实例上的 agent 做，面板不再从海外 TCP 探测。
    probe_mode TEXT NOT NULL DEFAULT 'agent',
    -- 上报凭证只存 SHA-256 摘要，明文只在生成脚本那一刻返回一次。
    -- 面板暴露在公网，库被读到也不能让人伪造上报触发换 IP。
    agent_token_hash TEXT NOT NULL DEFAULT '',
    agent_target TEXT NOT NULL DEFAULT '',
    agent_interval_sec INTEGER NOT NULL DEFAULT 60,
    agent_fail_threshold INTEGER NOT NULL DEFAULT 3,
    agent_last_seen BIGINT NOT NULL DEFAULT 0,
    agent_last_report BIGINT NOT NULL DEFAULT 0,
    agent_last_detail TEXT NOT NULL DEFAULT '',
    UNIQUE(account_id, region, instance_id)
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    created_at BIGINT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL DEFAULT 1,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS ddns_rules (
    id SERIAL PRIMARY KEY,
    provider TEXT NOT NULL DEFAULT 'cloudflare',
    zone TEXT NOT NULL,
    hostname TEXT NOT NULL,
    token_blob TEXT NOT NULL DEFAULT '',
    cf_account_id TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    want_ipv4 INTEGER NOT NULL DEFAULT 1,
    want_ipv6 INTEGER NOT NULL DEFAULT 0,
    ttl INTEGER NOT NULL DEFAULT 1,
    proxied INTEGER NOT NULL DEFAULT 0,
    interval_sec INTEGER NOT NULL DEFAULT 300,
    note TEXT NOT NULL DEFAULT '',
    last_check BIGINT NOT NULL DEFAULT 0,
    last_ipv4 TEXT NOT NULL DEFAULT '',
    last_ipv6 TEXT NOT NULL DEFAULT '',
    last_status TEXT NOT NULL DEFAULT '',
    fail_count INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    UNIQUE(provider, hostname)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL,
    last_seen BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    source TEXT PRIMARY KEY,
    fail_count INTEGER NOT NULL DEFAULT 0,
    last_failed_at BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_history (
    id SERIAL PRIMARY KEY,
    created_at BIGINT NOT NULL,
    ok INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_login_history_created
    ON login_history(created_at DESC);
"""

# 升级已有库时补的列。CREATE TABLE IF NOT EXISTS 对已存在的表什么都不做，
# 老库不会自动长出新字段 —— 这里逐条 ADD COLUMN IF NOT EXISTS 补齐。
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("ddns_rules", "cf_account_id", "TEXT NOT NULL DEFAULT ''"),
    ("ip_rules", "probe_mode", "TEXT NOT NULL DEFAULT 'agent'"),
    ("ip_rules", "agent_token_hash", "TEXT NOT NULL DEFAULT ''"),
    ("ip_rules", "agent_target", "TEXT NOT NULL DEFAULT ''"),
    ("ip_rules", "agent_interval_sec", "INTEGER NOT NULL DEFAULT 60"),
    ("ip_rules", "agent_fail_threshold", "INTEGER NOT NULL DEFAULT 3"),
    ("ip_rules", "agent_last_seen", "BIGINT NOT NULL DEFAULT 0"),
    ("ip_rules", "agent_last_report", "BIGINT NOT NULL DEFAULT 0"),
    ("ip_rules", "agent_last_detail", "TEXT NOT NULL DEFAULT ''"),
)

# 迁移用：表名 → 列名。顺序有依赖，accounts 必须先导入
_MIGRATION_TABLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "accounts",
        ("id", "label", "access_key", "secret_blob", "region", "proxy_blob",
         "note", "created_at"),
    ),
    ("scripts", ("id", "name", "body", "packages", "created_at")),
    (
        "keypairs",
        ("id", "account_id", "region", "key_name", "private_key", "created_at"),
    ),
    (
        "ip_rules",
        ("id", "account_id", "region", "instance_id", "enabled", "strategy",
         "check_mode", "check_port", "interval_sec", "fail_threshold",
         "allow_cidrs", "deny_cidrs", "max_attempts", "fail_count",
         "last_check", "last_change"),
    ),
    ("logs", ("id", "created_at", "kind", "target", "ok", "detail")),
    ("settings", ("key", "value", "updated_at")),
    (
        "sessions",
        ("token_hash", "created_at", "last_seen", "expires_at", "ip", "user_agent"),
    ),
    ("login_attempts", ("source", "fail_count", "last_failed_at")),
    (
        "login_history",
        ("id", "created_at", "ok", "ip", "user_agent", "detail"),
    ),
)


@dataclass
class Account:
    id: int
    label: str
    access_key: str
    region: str
    note: str
    created_at: int
    proxy: str | None = None

    def masked(self) -> str:
        if len(self.access_key) <= 8:
            return "*" * len(self.access_key)
        return f"{self.access_key[:4]}{'*' * 8}{self.access_key[-4:]}"

    def masked_proxy(self) -> str:
        return mask_proxy(self.proxy)


class Store:
    """所有持久化操作的入口。并发安全由 Postgres 和连接池保证。"""

    def __init__(
        self,
        data_dir: Path | str | None = None,
        dsn: str | None = None,
        schema: str | None = None,
    ) -> None:
        self.dir = Path(data_dir).expanduser() if data_dir else default_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.dsn = dsn or database_url()
        self.schema = schema or os.environ.get("AWS_HELPER_DB_SCHEMA", "public")
        self._fernet = Fernet(self._load_secret())

        try:
            self.pool = ConnectionPool(
                self.dsn,
                min_size=1,
                max_size=int(os.environ.get("AWS_HELPER_DB_POOL", "8")),
                open=True,
                timeout=15,
                kwargs={"row_factory": dict_row, "options": f"-c search_path={self.schema}"},
            )
            self.pool.wait(timeout=20)
        except Exception as exc:
            raise DatabaseError(
                f"无法连接 Postgres（{self._safe_dsn()}）: {exc}\n"
                "请确认数据库已启动、AWS_HELPER_DATABASE_URL 正确"
            ) from exc

        self._init_schema()
        self._migrate_from_sqlite()

    def _safe_dsn(self) -> str:
        """隐去连接串里的密码，用于报错和日志。"""
        try:
            info = psycopg.conninfo.conninfo_to_dict(self.dsn)
        except Exception:
            return "<dsn>"
        user = info.get("user", "")
        host = info.get("host", "")
        port = info.get("port", "")
        db = info.get("dbname", "")
        auth_part = f"{user}:***@" if info.get("password") else (f"{user}@" if user else "")
        return f"postgresql://{auth_part}{host}:{port}/{db}"

    def _init_schema(self) -> None:
        with self.pool.connection() as conn:
            conn.execute(f"CREATE SCHEMA IF NOT EXISTS {self.schema}")
            conn.execute(f"SET search_path TO {self.schema}")
            conn.execute(SCHEMA)
            for table, column, ddl in _ADDED_COLUMNS:
                # SCHEMA 里是 CREATE TABLE IF NOT EXISTS，对已存在的表不会加新列。
                # 升级上来的库要单独补，否则新字段的读写全部报 UndefinedColumn。
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {ddl}"
                )
            # 面板侧探测已下线。ADD COLUMN 的 DEFAULT 只作用于新行，
            # 升级上来的老规则仍是 'local'，不改就永远不会被上报驱动。
            conn.execute("UPDATE ip_rules SET probe_mode='agent' WHERE probe_mode<>'agent'")
            conn.commit()

    # ---------- SQLite 迁移 ----------

    def _legacy_sqlite_path(self) -> Path:
        return self.dir / "aws-helper.db"

    def _migrate_from_sqlite(self) -> None:
        """库为空且存在旧 SQLite 文件时，自动导入。

        只在 accounts 和 settings 都为空时才导入，避免重复迁移覆盖新数据。
        导入完成后给旧文件改名加 .migrated 后缀，下次启动不再处理。
        """
        legacy = self._legacy_sqlite_path()
        if not legacy.is_file():
            return
        if self._row_count("accounts") or self._row_count("settings"):
            return

        try:
            imported = self._import_sqlite(legacy)
        except Exception as exc:
            self.log("migrate", str(legacy), False, f"迁移失败: {exc}")
            return

        if imported:
            legacy.rename(legacy.with_suffix(".db.migrated"))
            summary = "，".join(f"{name} {n}" for name, n in imported.items() if n)
            self.log("migrate", "sqlite", True, f"已从 SQLite 迁移: {summary or '空库'}")

    def _import_sqlite(self, path: Path) -> dict[str, int]:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        existing = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        imported: dict[str, int] = {}
        try:
            with self.pool.connection() as pg:
                for table, columns in _MIGRATION_TABLES:
                    if table not in existing:
                        continue
                    available = {
                        row[1]
                        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
                    }
                    cols = [c for c in columns if c in available]
                    if not cols:
                        continue

                    rows = conn.execute(
                        f"SELECT {','.join(cols)} FROM {table}"
                    ).fetchall()
                    if not rows:
                        continue

                    placeholders = ",".join(["%s"] * len(cols))
                    pg.cursor().executemany(
                        f"INSERT INTO {table}({','.join(cols)}) VALUES({placeholders})"
                        " ON CONFLICT DO NOTHING",
                        [tuple(row[c] for c in cols) for row in rows],
                    )
                    imported[table] = len(rows)

                # SERIAL 序列不会随手工插入的 id 前进，必须校正
                for table, columns in _MIGRATION_TABLES:
                    if "id" in columns and table in imported:
                        pg.execute(
                            f"SELECT setval(pg_get_serial_sequence('{table}', 'id'),"
                            f" COALESCE((SELECT MAX(id) FROM {table}), 1))"
                        )
                pg.commit()
        finally:
            conn.close()
        return imported

    def _row_count(self, table: str) -> int:
        with self.pool.connection() as conn:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
        return int(row["n"]) if row else 0

    # ---------- 查询辅助 ----------

    def _fetchone(self, sql: str, args: Iterable[Any] = ()) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            return conn.execute(sql, tuple(args)).fetchone()

    def _fetchall(self, sql: str, args: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            return conn.execute(sql, tuple(args)).fetchall()

    def _execute(self, sql: str, args: Iterable[Any] = ()) -> int:
        with self.pool.connection() as conn:
            cur = conn.execute(sql, tuple(args))
            conn.commit()
            return cur.rowcount

    def _returning_id(self, sql: str, args: Iterable[Any] = ()) -> int:
        with self.pool.connection() as conn:
            row = conn.execute(sql, tuple(args)).fetchone()
            conn.commit()
        return int(row["id"]) if row else 0

    # ---------- 加密 ----------

    def _load_secret(self) -> bytes:
        env = os.environ.get("AWS_HELPER_SECRET")
        if env:
            return env.encode() if len(env) == 44 else Fernet.generate_key()
        key_file = self.dir / "secret.key"
        if key_file.exists():
            return key_file.read_bytes().strip()
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        os.chmod(key_file, 0o600)
        return key

    def _encrypt(self, plain: str) -> str:
        return self._fernet.encrypt(plain.encode()).decode()

    def _decrypt(self, blob: str) -> str:
        try:
            return self._fernet.decrypt(blob.encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError(
                "凭据解密失败：加密密钥与数据库不匹配。"
                "检查 AWS_HELPER_SECRET 或 secret.key 是否被更换。"
            ) from exc

    # ---------- 账号 ----------

    _ACCOUNT_COLS = "id,label,access_key,region,note,created_at,proxy_blob"

    def add_account(
        self,
        label: str,
        access_key: str,
        secret_key: str,
        region: str,
        note: str = "",
        proxy: str | None = None,
    ) -> int:
        return self._returning_id(
            "INSERT INTO accounts"
            "(label, access_key, secret_blob, region, note, proxy_blob, created_at)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (
                label,
                access_key,
                self._encrypt(secret_key),
                region,
                note,
                self._encrypt_proxy(proxy),
                int(time.time()),
            ),
        )

    def update_account(
        self,
        account_id: int,
        label: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str | None = None,
        note: str | None = None,
        proxy: str | None = None,
        clear_proxy: bool = False,
    ) -> None:
        """更新账号。传 None 表示该字段不变。

        secret_key 传 None 保留原密钥，方便编辑时不必重新输入。
        代理清空需显式传 clear_proxy=True，避免与"不修改"混淆。
        """
        if self._fetchone("SELECT 1 FROM accounts WHERE id=%s", (account_id,)) is None:
            raise LookupError(f"账号 {account_id} 不存在")

        sets: list[str] = []
        args: list[Any] = []
        for column, value in (
            ("label", label),
            ("access_key", access_key),
            ("region", region),
            ("note", note),
        ):
            if value is not None:
                sets.append(f"{column}=%s")
                args.append(value)

        if secret_key is not None:
            sets.append("secret_blob=%s")
            args.append(self._encrypt(secret_key))

        if clear_proxy:
            sets.append("proxy_blob=%s")
            args.append("")
        elif proxy is not None:
            sets.append("proxy_blob=%s")
            args.append(self._encrypt_proxy(proxy))

        if not sets:
            return
        args.append(account_id)
        self._execute(f"UPDATE accounts SET {','.join(sets)} WHERE id=%s", args)

    def _encrypt_proxy(self, proxy: str | None) -> str:
        normalized = normalize_proxy(proxy)
        return self._encrypt(normalized) if normalized else ""

    def _decrypt_proxy(self, blob: str) -> str | None:
        return self._decrypt(blob) if blob else None

    def _to_account(self, row: dict[str, Any]) -> Account:
        data = dict(row)
        proxy_blob = data.pop("proxy_blob", "")
        return Account(**data, proxy=self._decrypt_proxy(proxy_blob))

    def list_accounts(self) -> list[Account]:
        rows = self._fetchall(
            f"SELECT {self._ACCOUNT_COLS} FROM accounts ORDER BY id DESC"
        )
        return [self._to_account(r) for r in rows]

    def get_account(self, account_id: int) -> Account:
        row = self._fetchone(
            f"SELECT {self._ACCOUNT_COLS} FROM accounts WHERE id=%s", (account_id,)
        )
        if row is None:
            raise LookupError(f"账号 {account_id} 不存在")
        return self._to_account(row)

    def credentials(self, account_id: int, region: str | None = None) -> Credentials:
        row = self._fetchone(
            "SELECT access_key,secret_blob,region,proxy_blob FROM accounts WHERE id=%s",
            (account_id,),
        )
        if row is None:
            raise LookupError(f"账号 {account_id} 不存在")
        return Credentials(
            access_key=row["access_key"],
            secret_key=self._decrypt(row["secret_blob"]),
            region=region or row["region"],
            proxy=self._decrypt_proxy(row["proxy_blob"]),
        )

    def delete_account(self, account_id: int) -> None:
        self._execute("DELETE FROM accounts WHERE id=%s", (account_id,))

    # ---------- 脚本模板 ----------

    def save_script(self, name: str, body: str, packages: list[str] | None = None) -> int:
        return self._returning_id(
            "INSERT INTO scripts(name, body, packages, created_at) VALUES(%s,%s,%s,%s)"
            " ON CONFLICT(name) DO UPDATE SET body=excluded.body,"
            " packages=excluded.packages RETURNING id",
            (name, body, json.dumps(packages or []), int(time.time())),
        )

    def script(self, script_id: int) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT id,name,body,packages,created_at FROM scripts WHERE id=%s",
            (script_id,),
        )
        if row is None:
            return None
        item = dict(row)
        item["packages"] = json.loads(item["packages"])
        return item

    def update_script(
        self, script_id: int, name: str, body: str, packages: list[str] | None = None
    ) -> bool:
        """按 id 改模板，允许改名。

        跟 save_script 的区别是这条按 id 定位：save_script 走 name 冲突合并，
        改名会变成新建一条，原来那条还留着。编辑必须按 id。
        返回是否命中了记录。
        """
        row = self._fetchone(
            "UPDATE scripts SET name=%s, body=%s, packages=%s WHERE id=%s RETURNING id",
            (name, body, json.dumps(packages or []), script_id),
        )
        return row is not None

    def list_scripts(self) -> list[dict[str, Any]]:
        rows = self._fetchall(
            "SELECT id,name,body,packages,created_at FROM scripts ORDER BY id DESC"
        )
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "body": r["body"],
                "packages": json.loads(r["packages"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def delete_script(self, script_id: int) -> None:
        self._execute("DELETE FROM scripts WHERE id=%s", (script_id,))

    # ---------- 密钥对 ----------

    def save_keypair(
        self, account_id: int, region: str, key_name: str, private_key: str
    ) -> None:
        self._execute(
            "INSERT INTO keypairs(account_id, region, key_name, private_key, created_at)"
            " VALUES(%s,%s,%s,%s,%s)"
            " ON CONFLICT(account_id, region, key_name) DO UPDATE SET"
            " private_key=excluded.private_key",
            (account_id, region, key_name, self._encrypt(private_key), int(time.time())),
        )

    def get_private_key(self, account_id: int, region: str, key_name: str) -> str | None:
        row = self._fetchone(
            "SELECT private_key FROM keypairs"
            " WHERE account_id=%s AND region=%s AND key_name=%s",
            (account_id, region, key_name),
        )
        return self._decrypt(row["private_key"]) if row else None

    def list_keypairs(self) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT id,account_id,region,key_name,created_at FROM keypairs"
            " ORDER BY id DESC"
        )

    # ---------- 实例登录凭据 ----------

    def save_instance_creds(
        self,
        account_id: int,
        region: str,
        instance_id: str,
        *,
        auth_method: str,
        login_user: str,
        password: str | None = None,
        key_name: str = "",
        name: str = "",
        os_family: str = "linux",
        note: str = "",
    ) -> int:
        """记下这台实例怎么登录。

        password 传 None 表示沿用已存的（重装换了系统但密码没变时用）。
        密码和私钥一样用 Fernet 加密，接口默认只回掩码。
        """
        if auth_method not in ("password", "key"):
            raise ValueError(f"未知的登录方式: {auth_method}")

        now = int(time.time())
        existing = self._fetchone(
            "SELECT id, password_blob FROM instance_creds"
            " WHERE account_id=%s AND region=%s AND instance_id=%s",
            (account_id, region, instance_id),
        )
        if password:
            blob = self._encrypt(password)
        elif existing:
            blob = existing["password_blob"]
        else:
            blob = ""

        return self._returning_id(
            "INSERT INTO instance_creds(account_id, region, instance_id, name,"
            " auth_method, login_user, password_blob, key_name, os_family, note,"
            " created_at, updated_at)"
            " VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT(account_id, region, instance_id) DO UPDATE SET"
            " name=excluded.name, auth_method=excluded.auth_method,"
            " login_user=excluded.login_user, password_blob=excluded.password_blob,"
            " key_name=excluded.key_name, os_family=excluded.os_family,"
            " note=excluded.note, updated_at=excluded.updated_at"
            " RETURNING id",
            (
                account_id,
                region,
                instance_id,
                name,
                auth_method,
                login_user,
                blob,
                key_name,
                os_family,
                note,
                now,
                now,
            ),
        )

    @staticmethod
    def _strip_password_blob(row: dict[str, Any]) -> dict[str, Any]:
        """密文必须 pop 掉而不是留着。

        接口会把整个 dict 序列化给页面，留着密文等于把它公开了 ——
        虽然解不开，但没有任何理由送出去。
        """
        item = dict(row)
        item["has_password"] = bool(item.pop("password_blob", ""))
        return item

    def instance_creds(
        self, account_id: int, region: str, instance_id: str
    ) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT * FROM instance_creds"
            " WHERE account_id=%s AND region=%s AND instance_id=%s",
            (account_id, region, instance_id),
        )
        return self._strip_password_blob(row) if row else None

    def list_instance_creds(self, account_id: int, region: str) -> list[dict[str, Any]]:
        return [
            self._strip_password_blob(row)
            for row in self._fetchall(
                "SELECT * FROM instance_creds WHERE account_id=%s AND region=%s"
                " ORDER BY id DESC",
                (account_id, region),
            )
        ]

    def instance_password(self, account_id: int, region: str, instance_id: str) -> str:
        """取密码明文。只有用户显式点「查看」时才调。"""
        row = self._fetchone(
            "SELECT password_blob FROM instance_creds"
            " WHERE account_id=%s AND region=%s AND instance_id=%s",
            (account_id, region, instance_id),
        )
        if not row or not row["password_blob"]:
            raise DatabaseError("这台实例没有保存密码")
        return self._decrypt(row["password_blob"])

    def delete_instance_creds(self, account_id: int, region: str, instance_id: str) -> None:
        self._execute(
            "DELETE FROM instance_creds"
            " WHERE account_id=%s AND region=%s AND instance_id=%s",
            (account_id, region, instance_id),
        )

    # ---------- 换 IP 规则 ----------

    _RULE_DEFAULTS: dict[str, Any] = {
        "enabled": 1,
        "strategy": "eip",
        "check_mode": "tcp",
        "check_port": 22,
        "interval_sec": 300,
        "fail_threshold": 3,
        "allow_cidrs": "[]",
        "deny_cidrs": "[]",
        "max_attempts": 3,
        "probe_mode": "agent",
        "agent_target": "",
        "agent_interval_sec": 60,
        "agent_fail_threshold": 3,
    }

    def save_ip_rule(self, **kw: Any) -> int:
        required = ("account_id", "region", "instance_id")
        for key in required:
            if kw.get(key) in (None, ""):
                raise ValueError(f"缺少必填字段: {key}")

        fields = required + tuple(self._RULE_DEFAULTS)
        data: dict[str, Any] = {k: kw.get(k) for k in required}
        for key, default in self._RULE_DEFAULTS.items():
            value = kw.get(key)
            data[key] = default if value is None else value
        for key in ("allow_cidrs", "deny_cidrs"):
            if isinstance(data[key], list):
                data[key] = json.dumps(data[key])

        placeholders = ",".join(["%s"] * len(fields))
        updates = ",".join(
            f"{f}=excluded.{f}" for f in fields if f not in required
        )
        return self._returning_id(
            f"INSERT INTO ip_rules({','.join(fields)}) VALUES({placeholders})"
            f" ON CONFLICT(account_id, region, instance_id) DO UPDATE SET {updates}"
            " RETURNING id",
            tuple(data[f] for f in fields),
        )

    @staticmethod
    def _clean_rule(row: dict[str, Any]) -> dict[str, Any]:
        """规则出库时解开 JSON 字段并摘掉凭证摘要。

        摘要必须 pop 掉：规则列表会整个序列化给页面，摘要虽然不可逆，
        但送出去等于给暴力枚举提供了目标。只保留「有没有发过凭证」。
        """
        item = dict(row)
        item["allow_cidrs"] = json.loads(item["allow_cidrs"])
        item["deny_cidrs"] = json.loads(item["deny_cidrs"])
        item["agent_deployed"] = bool(item.pop("agent_token_hash", ""))
        return item

    def list_ip_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM ip_rules"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY id DESC"
        return [self._clean_rule(r) for r in self._fetchall(sql)]

    def update_rule_state(
        self,
        rule_id: int,
        fail_count: int | None = None,
        last_check: int | None = None,
        last_change: int | None = None,
    ) -> None:
        sets, args = [], []
        if fail_count is not None:
            sets.append("fail_count=%s")
            args.append(fail_count)
        if last_check is not None:
            sets.append("last_check=%s")
            args.append(last_check)
        if last_change is not None:
            sets.append("last_change=%s")
            args.append(last_change)
        if not sets:
            return
        args.append(rule_id)
        self._execute(f"UPDATE ip_rules SET {','.join(sets)} WHERE id=%s", args)

    def delete_ip_rule(self, rule_id: int) -> None:
        self._execute("DELETE FROM ip_rules WHERE id=%s", (rule_id,))

    def ip_rule(self, rule_id: int) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM ip_rules WHERE id=%s", (rule_id,))
        return self._clean_rule(row) if row else None

    def issue_agent_token(self, rule_id: int) -> str:
        """给规则发一个上报凭证，返回明文。

        只存 SHA-256 摘要 —— 面板暴露在公网，库被读到也不能让人伪造上报
        触发换 IP。明文只在这里返回一次，之后想要只能重新生成。
        """
        token = secrets.token_urlsafe(32)
        self._execute(
            "UPDATE ip_rules SET agent_token_hash=%s WHERE id=%s",
            (self._hash_token(token), rule_id),
        )
        return token

    def rule_by_agent_token(
        self, token: str, instance_id: str = ""
    ) -> dict[str, Any] | None:
        """按上报凭证找规则。凭证不对返回 None，不透露规则是否存在。

        开机时批量部署的实例共用一个凭证（user-data 在 RunInstances 之前
        定稿，那时实例 ID 还不存在），所以同一摘要可能对应多条规则。带上
        实例 ID 才能定位到具体哪一台；不带时只在唯一匹配下返回。
        """
        if not token:
            return None
        rows = self._fetchall(
            "SELECT * FROM ip_rules WHERE agent_token_hash=%s ORDER BY id",
            (self._hash_token(token),),
        )
        if not rows:
            return None
        if instance_id:
            for row in rows:
                if row["instance_id"] == instance_id:
                    return self._clean_rule(row)
            return None
        return self._clean_rule(rows[0]) if len(rows) == 1 else None

    def record_agent_reject(self, token: str, instance_id: str, kind: str) -> None:
        """记一次被拒的上报，把真实原因留在日志里。

        上报接口对外统一回「凭证无效」，不区分原因（那会向公网探测者确认
        凭证有效性）。但用户看到实例日志里的 401 时需要知道到底是哪种：
        重新生成脚本作废了旧凭证，还是脚本被复制到了别的机器。
        """
        digest = self._hash_token(token) if token else ""
        known = bool(
            digest
            and self._fetchone(
                "SELECT 1 FROM ip_rules WHERE agent_token_hash=%s", (digest,)
            )
        )
        if not token:
            reason = "上报未带凭证"
        elif known:
            reason = (
                f"凭证有效但实例 ID 不匹配（上报方自称 {instance_id or '未提供'}）"
                "，脚本可能被复制到了别的机器"
            )
        else:
            reason = (
                "凭证不在库里 —— 通常是又点了一次「生成部署脚本」，"
                "旧脚本已作废，需要把新脚本重新在实例上执行一遍"
            )
        self.log("autoip", instance_id or "未知实例", False, f"上报被拒（{kind}）: {reason}")

    def recent_agent_rejects(self, instance_id: str, limit: int = 3) -> list[dict[str, Any]]:
        """取这台实例最近的上报被拒记录，供面板的「检测」展示。"""
        rows = self._fetchall(
            "SELECT created_at, detail FROM logs"
            " WHERE kind='autoip' AND target=%s AND ok=0 AND detail LIKE '上报被拒%%'"
            " ORDER BY id DESC LIMIT %s",
            (instance_id, limit),
        )
        return [dict(r) for r in rows]

    def save_agent_token_hash(self, rule_id: int, token: str) -> None:
        """把已知明文的凭证摘要写到规则上。

        开机时批量部署用：一份 user-data 带同一个凭证，实例 ID 要等
        RunInstances 返回才知道，那时给每台各建一条规则、共用这个摘要。
        """
        self._execute(
            "UPDATE ip_rules SET agent_token_hash=%s WHERE id=%s",
            (self._hash_token(token), rule_id),
        )

    def touch_agent(
        self, rule_id: int, *, reported: bool = False, detail: str = ""
    ) -> None:
        """记一次 agent 心跳。reported=True 表示这次带了被墙上报。

        agent_last_seen 每次都更新，用来在面板显示「部署状态」——
        探测正常时脚本不上报，所以还是要有心跳才能区分「一切正常」和
        「脚本挂了/机器没了」。
        """
        now = int(time.time())
        if reported:
            self._execute(
                "UPDATE ip_rules SET agent_last_seen=%s, agent_last_report=%s,"
                " agent_last_detail=%s WHERE id=%s",
                (now, now, detail[:400], rule_id),
            )
        else:
            self._execute(
                "UPDATE ip_rules SET agent_last_seen=%s, agent_last_detail=%s"
                " WHERE id=%s",
                (now, detail[:400], rule_id),
            )

    # ---------- DDNS ----------

    _DDNS_DEFAULTS: dict[str, Any] = {
        "provider": "cloudflare",
        "cf_account_id": "",
        "enabled": 1,
        "want_ipv4": 1,
        "want_ipv6": 0,
        "ttl": 1,
        "proxied": 0,
        "interval_sec": 300,
        "note": "",
    }

    def save_ddns_rule(self, zone: str, hostname: str, token: str | None = None, **kw: Any) -> int:
        """新增或更新一条 DDNS 规则。

        token 传 None 表示沿用原有的 —— 编辑时不必重新粘贴 API Token，
        和账号编辑里 Secret Key 的处理保持一致。
        """
        zone = (zone or "").strip().lower()
        hostname = (hostname or "").strip().lower()
        if not zone:
            raise ValueError("缺少必填字段: zone")
        if not hostname:
            raise ValueError("缺少必填字段: hostname")
        if not hostname.endswith(zone):
            raise ValueError(f"主机名 {hostname} 不属于区域 {zone}")

        data: dict[str, Any] = {"zone": zone, "hostname": hostname}
        for key, default in self._DDNS_DEFAULTS.items():
            value = kw.get(key)
            data[key] = default if value is None else value
        for flag in ("enabled", "want_ipv4", "want_ipv6", "proxied"):
            data[flag] = 1 if data[flag] else 0
        if not (data["want_ipv4"] or data["want_ipv6"]):
            raise ValueError("至少要开启 IPv4 或 IPv6 之一")

        existing = self._fetchone(
            "SELECT id, token_blob FROM ddns_rules WHERE provider=%s AND hostname=%s",
            (data["provider"], hostname),
        )
        if token:
            blob = self._encrypt(token.strip())
        elif existing:
            blob = existing["token_blob"]
        else:
            raise ValueError("新建规则必须提供 API Token")

        # provider 已经在 _DDNS_DEFAULTS 里，别再拼一次，否则 INSERT 会重复列名
        fields = ("zone", "hostname", "token_blob") + tuple(self._DDNS_DEFAULTS)
        values = {**data, "token_blob": blob}
        ordered = tuple(values[f] for f in fields)
        updates = ",".join(
            f"{f}=excluded.{f}" for f in fields if f not in ("provider", "hostname")
        )
        return self._returning_id(
            f"INSERT INTO ddns_rules({','.join(fields)}, created_at)"
            f" VALUES({','.join(['%s'] * len(fields))}, %s)"
            f" ON CONFLICT(provider, hostname) DO UPDATE SET {updates}"
            " RETURNING id",
            (*ordered, int(time.time())),
        )

    def list_ddns_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        """列出规则。绝不返回 token 明文或密文，只给「有没有配」。"""
        sql = "SELECT * FROM ddns_rules"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY id DESC"
        out = []
        for row in self._fetchall(sql):
            item = dict(row)
            item["has_token"] = bool(item.pop("token_blob", ""))
            out.append(item)
        return out

    def ddns_token(self, rule_id: int) -> str:
        row = self._fetchone("SELECT token_blob FROM ddns_rules WHERE id=%s", (rule_id,))
        if not row or not row["token_blob"]:
            raise DatabaseError(f"DDNS 规则 {rule_id} 没有保存 API Token")
        return self._decrypt(row["token_blob"])

    def ddns_rule(self, rule_id: int) -> dict[str, Any] | None:
        row = self._fetchone("SELECT * FROM ddns_rules WHERE id=%s", (rule_id,))
        return dict(row) if row else None

    def update_ddns_state(
        self,
        rule_id: int,
        last_check: int | None = None,
        last_ipv4: str | None = None,
        last_ipv6: str | None = None,
        last_status: str | None = None,
        fail_count: int | None = None,
    ) -> None:
        sets, args = [], []
        for column, value in (
            ("last_check", last_check),
            ("last_ipv4", last_ipv4),
            ("last_ipv6", last_ipv6),
            ("last_status", last_status),
            ("fail_count", fail_count),
        ):
            if value is not None:
                sets.append(f"{column}=%s")
                args.append(value[:400] if isinstance(value, str) else value)
        if not sets:
            return
        args.append(rule_id)
        self._execute(f"UPDATE ddns_rules SET {','.join(sets)} WHERE id=%s", args)

    def delete_ddns_rule(self, rule_id: int) -> None:
        self._execute("DELETE FROM ddns_rules WHERE id=%s", (rule_id,))

    # ---------- 日志 ----------

    def log(self, kind: str, target: str = "", ok: bool = True, detail: str = "") -> None:
        self._execute(
            "INSERT INTO logs(created_at, kind, target, ok, detail)"
            " VALUES(%s,%s,%s,%s,%s)",
            (int(time.time()), kind, target, 1 if ok else 0, detail[:4000]),
        )

    def list_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT id,created_at,kind,target,ok,detail FROM logs"
            " ORDER BY created_at DESC, id DESC LIMIT %s",
            (limit,),
        )

    # ---------- 设置 ----------

    def set_setting(self, key: str, value: str) -> None:
        self._execute(
            "INSERT INTO settings(key, value, updated_at) VALUES(%s,%s,%s)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
            " updated_at=excluded.updated_at",
            (key, value, int(time.time())),
        )

    def get_setting(self, key: str) -> str | None:
        row = self._fetchone("SELECT value FROM settings WHERE key=%s", (key,))
        return row["value"] if row else None

    def setting_updated_at(self, key: str) -> int:
        row = self._fetchone("SELECT updated_at FROM settings WHERE key=%s", (key,))
        return int(row["updated_at"]) if row else 0

    # ---------- 登录密码 ----------

    PASSWORD_KEY = "admin_password_hash"

    def has_password(self) -> bool:
        return bool(self.get_setting(self.PASSWORD_KEY))

    def set_password(self, password: str, validate: bool = True) -> None:
        """写入新密码。会顺带作废所有现有会话 —— 改密必须让旧登录失效。"""
        if validate:
            auth.validate_strength(password)
        self.set_setting(self.PASSWORD_KEY, auth.hash_password(password))
        self.clear_sessions()

    def verify_login(self, password: str) -> bool:
        """校验密码，顺便在参数过时时静默升级哈希。"""
        stored = self.get_setting(self.PASSWORD_KEY)
        if not stored:
            return False
        if not auth.verify_password(password, stored):
            return False
        if auth.needs_rehash(stored):
            self.set_setting(self.PASSWORD_KEY, auth.hash_password(password))
        return True

    def password_changed_at(self) -> int:
        return self.setting_updated_at(self.PASSWORD_KEY)

    # ---------- 会话 ----------

    @staticmethod
    def _hash_token(token: str) -> str:
        """会话令牌按哈希存储，库被读走也无法冒用登录态。"""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(
        self, ttl: int = 86400, ip: str = "", user_agent: str = ""
    ) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        self._execute(
            "INSERT INTO sessions"
            "(token_hash, created_at, last_seen, expires_at, ip, user_agent)"
            " VALUES(%s,%s,%s,%s,%s,%s)",
            (self._hash_token(token), now, now, now + ttl, ip, user_agent[:300]),
        )
        return token

    def touch_session(self, token: str) -> bool:
        """校验会话是否有效，同时刷新 last_seen。过期会话立即删除。"""
        now = int(time.time())
        token_hash = self._hash_token(token)
        row = self._fetchone(
            "SELECT expires_at FROM sessions WHERE token_hash=%s", (token_hash,)
        )
        if row is None:
            return False
        if int(row["expires_at"]) <= now:
            self._execute("DELETE FROM sessions WHERE token_hash=%s", (token_hash,))
            return False
        self._execute(
            "UPDATE sessions SET last_seen=%s WHERE token_hash=%s", (now, token_hash)
        )
        return True

    def list_sessions(self, current_token: str | None = None) -> list[dict[str, Any]]:
        now = int(time.time())
        self._execute("DELETE FROM sessions WHERE expires_at<=%s", (now,))
        current_hash = self._hash_token(current_token) if current_token else None
        rows = self._fetchall(
            "SELECT token_hash,created_at,last_seen,expires_at,ip,user_agent"
            " FROM sessions ORDER BY last_seen DESC"
        )
        out = []
        for row in rows:
            item = dict(row)
            item["current"] = item["token_hash"] == current_hash
            # 只回传前缀，避免整串哈希外泄后被用于枚举
            item["id"] = item.pop("token_hash")[:12]
            out.append(item)
        return out

    def revoke_session(self, session_id: str) -> bool:
        return self._execute(
            "DELETE FROM sessions WHERE left(token_hash, 12)=%s", (session_id,)
        ) > 0

    def revoke_session_token(self, token: str) -> None:
        self._execute(
            "DELETE FROM sessions WHERE token_hash=%s", (self._hash_token(token),)
        )

    def clear_sessions(self, keep_token: str | None = None) -> int:
        if keep_token:
            return self._execute(
                "DELETE FROM sessions WHERE token_hash<>%s",
                (self._hash_token(keep_token),),
            )
        return self._execute("DELETE FROM sessions")

    # ---------- 登录失败限流 ----------

    def lock_state(self, source: str) -> auth.LockState:
        row = self._fetchone(
            "SELECT fail_count,last_failed_at FROM login_attempts WHERE source=%s",
            (source,),
        )
        if row is None:
            return auth.evaluate_lock(0, 0, int(time.time()))
        state = auth.evaluate_lock(
            int(row["fail_count"]), int(row["last_failed_at"]), int(time.time())
        )
        if not state.locked and state.fail_count == 0 and int(row["fail_count"]):
            self.reset_attempts(source)
        return state

    def record_failure(self, source: str) -> auth.LockState:
        now = int(time.time())
        self._execute(
            "INSERT INTO login_attempts(source, fail_count, last_failed_at)"
            " VALUES(%s,1,%s)"
            " ON CONFLICT(source) DO UPDATE SET"
            " fail_count=login_attempts.fail_count+1,"
            " last_failed_at=excluded.last_failed_at",
            (source, now),
        )
        return self.lock_state(source)

    def reset_attempts(self, source: str) -> None:
        self._execute("DELETE FROM login_attempts WHERE source=%s", (source,))

    # ---------- 登录历史 ----------

    def record_login(
        self, ok: bool, ip: str = "", user_agent: str = "", detail: str = ""
    ) -> None:
        self._execute(
            "INSERT INTO login_history(created_at, ok, ip, user_agent, detail)"
            " VALUES(%s,%s,%s,%s,%s)",
            (int(time.time()), 1 if ok else 0, ip, user_agent[:300], detail[:500]),
        )

    def list_login_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._fetchall(
            "SELECT id,created_at,ok,ip,user_agent,detail FROM login_history"
            " ORDER BY created_at DESC, id DESC LIMIT %s",
            (limit,),
        )

    def close(self) -> None:
        self.pool.close()
