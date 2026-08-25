"""密码哈希与登录安全。

面板持有 AWS 凭据，登录口是唯一屏障，所以：
- 密码用 PBKDF2-SHA256 加盐哈希，绝不明文或可解密存储
- 哈希串自带算法和迭代次数，将来能在验证成功时无痛升级参数
- 校验用 compare_digest，避免按字节比较泄漏时序信息
- 连续失败按 IP 锁定，挡住暴力破解
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 260_000
SALT_BYTES = 16
MIN_LENGTH = 10

FAIL_LIMIT = 5
LOCK_SECONDS = 900


class PasswordError(ValueError):
    """密码不符合要求。"""


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    """返回 `算法$迭代次数$盐$摘要` 格式的哈希串。"""
    if not password:
        raise PasswordError("密码不能为空")
    salt = secrets.token_hex(SALT_BYTES)
    digest = _derive(password, salt, iterations)
    return f"{ALGORITHM}${iterations}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    """校验密码。哈希串格式错误时返回 False，不抛异常。"""
    if not password or not stored:
        return False
    try:
        algorithm, raw_iterations, salt, expected = stored.split("$", 3)
        iterations = int(raw_iterations)
    except (ValueError, AttributeError):
        return False
    if algorithm != ALGORITHM or iterations < 1:
        return False
    return hmac.compare_digest(_derive(password, salt, iterations), expected)


def needs_rehash(stored: str) -> bool:
    """判断哈希是否用了过时的参数，验证成功后可据此静默升级。"""
    try:
        algorithm, raw_iterations, _, _ = stored.split("$", 3)
        return algorithm != ALGORITHM or int(raw_iterations) < ITERATIONS
    except (ValueError, AttributeError):
        return True


def validate_strength(password: str) -> None:
    """密码强度要求。太弱直接拒绝，不给"建议"了事。"""
    if len(password) < MIN_LENGTH:
        raise PasswordError(f"密码至少 {MIN_LENGTH} 位")
    if len(password) > 200:
        raise PasswordError("密码过长（上限 200 位）")
    if password.strip() != password:
        raise PasswordError("密码首尾不能有空格")

    kinds = sum(
        bool(pattern.search(password))
        for pattern in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"\d"),
            re.compile(r"[^\w\s]"),
        )
    )
    if kinds < 3:
        raise PasswordError("密码需包含大写、小写、数字、符号中的至少三类")
    if _is_common(password):
        raise PasswordError("这个密码太常见，换一个")


_COMMON = {
    "password",
    "passw0rd",
    "password1",
    "password123",
    "admin123",
    "administrator",
    "qwertyuiop",
    "1234567890",
    "letmein123",
    "iloveyou123",
    "welcome123",
    "changeme123",
    "aws1234567",
    "abc123456789",
}


def _is_common(password: str) -> bool:
    lowered = password.lower()
    if lowered in _COMMON:
        return True
    # 全同字符或纯连续数字，长度再长也没有强度
    if len(set(lowered)) <= 2:
        return True
    digits = "1234567890" * 3
    return lowered in digits or lowered in digits[::-1]


def generate_password(length: int = 16) -> str:
    """生成满足强度要求的随机密码，用于首次启动和 CLI 重置。"""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    symbols = "!@#$%^&*-_=+"
    while True:
        body = "".join(secrets.choice(alphabet) for _ in range(length - 2))
        candidate = body + secrets.choice(symbols) + secrets.choice("23456789")
        try:
            validate_strength(candidate)
            return candidate
        except PasswordError:
            continue


def _derive(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("ascii"), iterations
    ).hex()


@dataclass(frozen=True)
class LockState:
    """某个来源当前的登录限制状态。"""

    locked: bool
    fail_count: int
    retry_after: int

    @property
    def remaining_attempts(self) -> int:
        return max(0, FAIL_LIMIT - self.fail_count)


def evaluate_lock(
    fail_count: int, last_failed_at: int, now: int, window: int = LOCK_SECONDS
) -> LockState:
    """按失败次数和最近失败时间判断是否锁定。

    锁定期满自动解封，不需要额外的清理任务。
    """
    if fail_count < FAIL_LIMIT:
        return LockState(False, fail_count, 0)
    elapsed = now - last_failed_at
    if elapsed >= window:
        return LockState(False, 0, 0)
    return LockState(True, fail_count, window - elapsed)
