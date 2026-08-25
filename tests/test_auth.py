"""密码哈希、强度校验与登录锁定的单元测试。"""

from __future__ import annotations

import pytest

from aws_helper import auth


# ---------- 哈希 ----------


def test_hash_format():
    parts = auth.hash_password("Str0ng!Passw0rd").split("$")
    assert len(parts) == 4
    assert parts[0] == auth.ALGORITHM
    assert int(parts[1]) == auth.ITERATIONS


def test_hash_is_salted():
    """同一密码两次哈希必须不同，否则彩虹表可用。"""
    a = auth.hash_password("Str0ng!Passw0rd")
    b = auth.hash_password("Str0ng!Passw0rd")
    assert a != b
    assert auth.verify_password("Str0ng!Passw0rd", a)
    assert auth.verify_password("Str0ng!Passw0rd", b)


def test_password_not_recoverable_from_hash():
    stored = auth.hash_password("Str0ng!Passw0rd")
    assert "Str0ng" not in stored
    assert "Passw0rd" not in stored


def test_verify_correct_and_wrong():
    stored = auth.hash_password("Str0ng!Passw0rd")
    assert auth.verify_password("Str0ng!Passw0rd", stored)
    assert not auth.verify_password("str0ng!passw0rd", stored)
    assert not auth.verify_password("Str0ng!Passw0rd ", stored)


@pytest.mark.parametrize(
    "stored",
    ["", "garbage", "pbkdf2_sha256$abc$salt$digest", "md5$1$s$d", "a$b$c"],
)
def test_verify_rejects_malformed_hash(stored):
    assert auth.verify_password("anything", stored) is False


def test_verify_rejects_empty_password():
    assert not auth.verify_password("", auth.hash_password("x"))


def test_hash_empty_password_rejected():
    with pytest.raises(auth.PasswordError):
        auth.hash_password("")


def test_needs_rehash():
    assert not auth.needs_rehash(auth.hash_password("Str0ng!Passw0rd"))
    assert auth.needs_rehash("pbkdf2_sha256$1000$salt$digest")
    assert auth.needs_rehash("md5$260000$salt$digest")
    assert auth.needs_rehash("garbage")


def test_low_iteration_hash_still_verifies():
    """老参数的哈希必须仍能通过验证，否则升级会把用户锁在门外。"""
    stored = auth.hash_password("Str0ng!Passw0rd", iterations=1000)
    assert auth.verify_password("Str0ng!Passw0rd", stored)
    assert auth.needs_rehash(stored)


# ---------- 强度 ----------


@pytest.mark.parametrize(
    "password",
    ["Str0ng!Passw0rd", "aB3$aB3$aB3$", "Xk9#mQ2vLp4w", "correct-Horse9"],
)
def test_accepts_strong_passwords(password):
    auth.validate_strength(password)


@pytest.mark.parametrize(
    "password,msg",
    [
        ("Ab3$x", "至少"),
        ("", "至少"),
        ("alllowercase123", "至少三类"),
        ("ALLUPPERCASE123", "至少三类"),
        ("password123", "至少三类"),
        ("aaaaaaaaaaaaa", "至少三类"),
        (" Str0ng!Pass ", "首尾不能有空格"),
        ("A" * 201 + "b3$", "过长"),
    ],
)
def test_rejects_weak_passwords(password, msg):
    with pytest.raises(auth.PasswordError, match=msg):
        auth.validate_strength(password)


def test_rejects_common_password():
    with pytest.raises(auth.PasswordError):
        auth.validate_strength("Password123")


def test_generated_password_is_strong():
    for _ in range(20):
        auth.validate_strength(auth.generate_password())


def test_generated_passwords_differ():
    assert len({auth.generate_password() for _ in range(20)}) == 20


# ---------- 锁定 ----------


def test_no_lock_below_limit():
    state = auth.evaluate_lock(auth.FAIL_LIMIT - 1, 1000, 1000)
    assert not state.locked
    assert state.remaining_attempts == 1


def test_lock_at_limit():
    state = auth.evaluate_lock(auth.FAIL_LIMIT, 1000, 1000)
    assert state.locked
    assert state.retry_after == auth.LOCK_SECONDS
    assert state.remaining_attempts == 0


def test_lock_expires_after_window():
    """锁定期满自动解封，不需要人工干预或清理任务。"""
    now = 1000 + auth.LOCK_SECONDS
    state = auth.evaluate_lock(auth.FAIL_LIMIT, 1000, now)
    assert not state.locked
    assert state.fail_count == 0


def test_lock_countdown_shrinks():
    state = auth.evaluate_lock(auth.FAIL_LIMIT, 1000, 1000 + 300)
    assert state.locked
    assert state.retry_after == auth.LOCK_SECONDS - 300
