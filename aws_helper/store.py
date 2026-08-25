"""SQLite 持久层：登录凭据、账号、脚本模板、换 IP 规则、会话、日志。

AWS Secret Key 与代理地址用 Fernet 对称加密后落盘，密钥取自 AWS_HELPER_SECRET；
未设置时自动生成并存到数据目录下 secret.key（权限 0600）。
面板登录密码走单向哈希，会话令牌只存 SHA-256 摘要，两者都不可逆。
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
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from . import auth
from .core.aws import Credentials, mask_proxy, normalize_proxy

def default_dir() -> Path:
    """数据目录。每次调用都重读环境变量，便于测试隔离和运行时切换。"""
    return Path(os.environ.get("AWS_HELPER_DATA", "~/.aws-helper")).expanduser()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    access_key TEXT NOT NULL,
    secret_blob TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT 'us-east-1',
    proxy_blob TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL,
    packages TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keypairs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    region TEXT NOT NULL,
    key_name TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(account_id, region, key_name)
);

CREATE TABLE IF NOT EXISTS ip_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    last_check INTEGER NOT NULL DEFAULT 0,
    last_change INTEGER NOT NULL DEFAULT 0,
    UNIQUE(account_id, region, instance_id)
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL DEFAULT 1,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    source TEXT PRIMARY KEY,
    fail_count INTEGER NOT NULL DEFAULT 0,
    last_failed_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_login_history_created
    ON login_history(created_at DESC);
"""


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
    """所有持久化操作的入口。线程安全依赖 SQLite 自身的锁。"""

    def __init__(self, data_dir: Path | str | None = None) -> None:
        self.dir = Path(data_dir).expanduser() if data_dir else default_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.dir / "aws-helper.db"
        self._fernet = Fernet(self._load_secret())
        self.conn = _connect(self.db_path)
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """为已存在的旧库补齐后加的列，让升级不需要删库。"""
        cols = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(accounts)").fetchall()
        }
        if "proxy_blob" not in cols:
            self.conn.execute(
                "ALTER TABLE accounts ADD COLUMN proxy_blob TEXT NOT NULL DEFAULT ''"
            )

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
        cur = self.conn.execute(
            "INSERT INTO accounts"
            "(label, access_key, secret_blob, region, note, proxy_blob, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
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
        self.conn.commit()
        return int(cur.lastrowid or 0)

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
        if self.conn.execute(
            "SELECT 1 FROM accounts WHERE id=?", (account_id,)
        ).fetchone() is None:
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
                sets.append(f"{column}=?")
                args.append(value)

        if secret_key is not None:
            sets.append("secret_blob=?")
            args.append(self._encrypt(secret_key))

        if clear_proxy:
            sets.append("proxy_blob=?")
            args.append("")
        elif proxy is not None:
            sets.append("proxy_blob=?")
            args.append(self._encrypt_proxy(proxy))

        if not sets:
            return
        args.append(account_id)
        self.conn.execute(
            f"UPDATE accounts SET {','.join(sets)} WHERE id=?", args
        )
        self.conn.commit()

    def _encrypt_proxy(self, proxy: str | None) -> str:
        normalized = normalize_proxy(proxy)
        return self._encrypt(normalized) if normalized else ""

    def _decrypt_proxy(self, blob: str) -> str | None:
        return self._decrypt(blob) if blob else None

    def _to_account(self, row: sqlite3.Row) -> Account:
        data = dict(row)
        proxy_blob = data.pop("proxy_blob", "")
        return Account(**data, proxy=self._decrypt_proxy(proxy_blob))

    def list_accounts(self) -> list[Account]:
        rows = self.conn.execute(
            f"SELECT {self._ACCOUNT_COLS} FROM accounts ORDER BY id DESC"
        ).fetchall()
        return [self._to_account(r) for r in rows]

    def get_account(self, account_id: int) -> Account:
        row = self.conn.execute(
            f"SELECT {self._ACCOUNT_COLS} FROM accounts WHERE id=?",
            (account_id,),
        ).fetchone()
        if row is None:
            raise LookupError(f"账号 {account_id} 不存在")
        return self._to_account(row)

    def credentials(self, account_id: int, region: str | None = None) -> Credentials:
        row = self.conn.execute(
            "SELECT access_key,secret_blob,region,proxy_blob FROM accounts WHERE id=?",
            (account_id,),
        ).fetchone()
        if row is None:
            raise LookupError(f"账号 {account_id} 不存在")
        return Credentials(
            access_key=row["access_key"],
            secret_key=self._decrypt(row["secret_blob"]),
            region=region or row["region"],
            proxy=self._decrypt_proxy(row["proxy_blob"]),
        )

    def delete_account(self, account_id: int) -> None:
        self.conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        self.conn.commit()

    # ---------- 脚本模板 ----------

    def save_script(self, name: str, body: str, packages: list[str] | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO scripts(name, body, packages, created_at) VALUES(?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET body=excluded.body,"
            " packages=excluded.packages",
            (name, body, json.dumps(packages or []), int(time.time())),
        )
        self.conn.commit()
        if cur.lastrowid:
            return int(cur.lastrowid)
        row = self.conn.execute("SELECT id FROM scripts WHERE name=?", (name,)).fetchone()
        return int(row["id"])

    def list_scripts(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id,name,body,packages,created_at FROM scripts ORDER BY id DESC"
        ).fetchall()
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
        self.conn.execute("DELETE FROM scripts WHERE id=?", (script_id,))
        self.conn.commit()

    # ---------- 密钥对 ----------

    def save_keypair(
        self, account_id: int, region: str, key_name: str, private_key: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO keypairs(account_id, region, key_name, private_key, created_at)"
            " VALUES(?,?,?,?,?)"
            " ON CONFLICT(account_id, region, key_name) DO UPDATE SET"
            " private_key=excluded.private_key",
            (account_id, region, key_name, self._encrypt(private_key), int(time.time())),
        )
        self.conn.commit()

    def get_private_key(self, account_id: int, region: str, key_name: str) -> str | None:
        row = self.conn.execute(
            "SELECT private_key FROM keypairs WHERE account_id=? AND region=? AND key_name=?",
            (account_id, region, key_name),
        ).fetchone()
        return self._decrypt(row["private_key"]) if row else None

    def list_keypairs(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id,account_id,region,key_name,created_at FROM keypairs ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

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
        placeholders = ",".join("?" for _ in fields)
        updates = ",".join(
            f"{f}=excluded.{f}" for f in fields if f not in ("account_id", "region", "instance_id")
        )
        cur = self.conn.execute(
            f"INSERT INTO ip_rules({','.join(fields)}) VALUES({placeholders})"
            f" ON CONFLICT(account_id, region, instance_id) DO UPDATE SET {updates}",
            tuple(data[f] for f in fields),
        )
        self.conn.commit()
        if cur.lastrowid:
            return int(cur.lastrowid)
        row = self.conn.execute(
            "SELECT id FROM ip_rules WHERE account_id=? AND region=? AND instance_id=?",
            (data["account_id"], data["region"], data["instance_id"]),
        ).fetchone()
        return int(row["id"])

    def list_ip_rules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM ip_rules"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY id DESC"
        rows = self.conn.execute(sql).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["allow_cidrs"] = json.loads(item["allow_cidrs"])
            item["deny_cidrs"] = json.loads(item["deny_cidrs"])
            out.append(item)
        return out

    def update_rule_state(
        self,
        rule_id: int,
        fail_count: int | None = None,
        last_check: int | None = None,
        last_change: int | None = None,
    ) -> None:
        sets, args = [], []
        if fail_count is not None:
            sets.append("fail_count=?")
            args.append(fail_count)
        if last_check is not None:
            sets.append("last_check=?")
            args.append(last_check)
        if last_change is not None:
            sets.append("last_change=?")
            args.append(last_change)
        if not sets:
            return
        args.append(rule_id)
        self.conn.execute(f"UPDATE ip_rules SET {','.join(sets)} WHERE id=?", args)
        self.conn.commit()

    def delete_ip_rule(self, rule_id: int) -> None:
        self.conn.execute("DELETE FROM ip_rules WHERE id=?", (rule_id,))
        self.conn.commit()

    # ---------- 日志 ----------

    def log(self, kind: str, target: str = "", ok: bool = True, detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO logs(created_at, kind, target, ok, detail) VALUES(?,?,?,?,?)",
            (int(time.time()), kind, target, 1 if ok else 0, detail[:4000]),
        )
        self.conn.commit()

    def list_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id,created_at,kind,target,ok,detail FROM logs"
            " ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------- 设置 ----------

    def set_setting(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO settings(key, value, updated_at) VALUES(?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
            " updated_at=excluded.updated_at",
            (key, value, int(time.time())),
        )
        self.conn.commit()

    def get_setting(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def setting_updated_at(self, key: str) -> int:
        row = self.conn.execute(
            "SELECT updated_at FROM settings WHERE key=?", (key,)
        ).fetchone()
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
        self.conn.execute(
            "INSERT INTO sessions(token_hash, created_at, last_seen, expires_at, ip, user_agent)"
            " VALUES(?,?,?,?,?,?)",
            (self._hash_token(token), now, now, now + ttl, ip, user_agent[:300]),
        )
        self.conn.commit()
        return token

    def touch_session(self, token: str) -> bool:
        """校验会话是否有效，同时刷新 last_seen。过期会话立即删除。"""
        now = int(time.time())
        token_hash = self._hash_token(token)
        row = self.conn.execute(
            "SELECT expires_at FROM sessions WHERE token_hash=?", (token_hash,)
        ).fetchone()
        if row is None:
            return False
        if int(row["expires_at"]) <= now:
            self.conn.execute(
                "DELETE FROM sessions WHERE token_hash=?", (token_hash,)
            )
            self.conn.commit()
            return False
        self.conn.execute(
            "UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, token_hash)
        )
        self.conn.commit()
        return True

    def list_sessions(self, current_token: str | None = None) -> list[dict[str, Any]]:
        now = int(time.time())
        self.conn.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
        self.conn.commit()
        current_hash = self._hash_token(current_token) if current_token else None
        rows = self.conn.execute(
            "SELECT token_hash,created_at,last_seen,expires_at,ip,user_agent"
            " FROM sessions ORDER BY last_seen DESC"
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["current"] = item["token_hash"] == current_hash
            # 只回传前缀，避免整串哈希外泄后被用于枚举
            item["id"] = item.pop("token_hash")[:12]
            out.append(item)
        return out

    def revoke_session(self, session_id: str) -> bool:
        cur = self.conn.execute(
            "DELETE FROM sessions WHERE substr(token_hash,1,12)=?", (session_id,)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def revoke_session_token(self, token: str) -> None:
        self.conn.execute(
            "DELETE FROM sessions WHERE token_hash=?", (self._hash_token(token),)
        )
        self.conn.commit()

    def clear_sessions(self, keep_token: str | None = None) -> int:
        if keep_token:
            cur = self.conn.execute(
                "DELETE FROM sessions WHERE token_hash<>?",
                (self._hash_token(keep_token),),
            )
        else:
            cur = self.conn.execute("DELETE FROM sessions")
        self.conn.commit()
        return cur.rowcount

    # ---------- 登录失败限流 ----------

    def lock_state(self, source: str) -> auth.LockState:
        row = self.conn.execute(
            "SELECT fail_count,last_failed_at FROM login_attempts WHERE source=?",
            (source,),
        ).fetchone()
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
        self.conn.execute(
            "INSERT INTO login_attempts(source, fail_count, last_failed_at)"
            " VALUES(?,1,?)"
            " ON CONFLICT(source) DO UPDATE SET"
            " fail_count=login_attempts.fail_count+1, last_failed_at=excluded.last_failed_at",
            (source, now),
        )
        self.conn.commit()
        return self.lock_state(source)

    def reset_attempts(self, source: str) -> None:
        self.conn.execute("DELETE FROM login_attempts WHERE source=?", (source,))
        self.conn.commit()

    # ---------- 登录历史 ----------

    def record_login(
        self, ok: bool, ip: str = "", user_agent: str = "", detail: str = ""
    ) -> None:
        self.conn.execute(
            "INSERT INTO login_history(created_at, ok, ip, user_agent, detail)"
            " VALUES(?,?,?,?,?)",
            (int(time.time()), 1 if ok else 0, ip, user_agent[:300], detail[:500]),
        )
        self.conn.commit()

    def list_login_history(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id,created_at,ok,ip,user_agent,detail FROM login_history"
            " ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self.conn.close()
