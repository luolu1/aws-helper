"""命令行工具：忘记密码时在服务器上重置。

    python3 -m aws_helper.cli reset-password            # 生成随机密码
    python3 -m aws_helper.cli reset-password --password '...'
    python3 -m aws_helper.cli status
    python3 -m aws_helper.cli logout-all

必须能在面板打不开、密码全忘的情况下工作，所以只依赖本地数据目录，
不经过任何网络请求或登录校验。
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from . import auth
from .store import Store, default_dir


def _fmt(ts: int) -> str:
    if not ts:
        return "从未"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def cmd_reset_password(args: argparse.Namespace) -> int:
    store = Store(args.data_dir)
    try:
        if args.password:
            password = args.password
            try:
                auth.validate_strength(password)
            except auth.PasswordError as exc:
                if not args.force:
                    print(f"密码不符合要求: {exc}", file=sys.stderr)
                    print("确实要用这个密码请加 --force", file=sys.stderr)
                    return 2
                print(f"警告: {exc}（--force 已忽略）", file=sys.stderr)
            store.set_password(password, validate=False)
            shown = "（使用你指定的密码）"
        else:
            password = auth.generate_password()
            store.set_password(password, validate=False)
            shown = f"新密码: {password}"

        store.log("auth", "password", True, "通过 CLI 重置登录密码")
        print("密码已重置，所有登录会话已失效。")
        print(f"  数据目录: {store.dir}")
        print(f"  {shown}")
        return 0
    finally:
        store.close()


def cmd_status(args: argparse.Namespace) -> int:
    store = Store(args.data_dir)
    try:
        sessions = store.list_sessions()
        history = store.list_login_history(5)
        print(f"数据目录    : {store.dir}")
        print(f"已设置密码  : {'是' if store.has_password() else '否'}")
        print(f"密码更新于  : {_fmt(store.password_changed_at())}")
        print(f"AWS 账号数  : {len(store.list_accounts())}")
        print(f"活跃会话    : {len(sessions)}")
        for item in sessions:
            print(
                f"  - {item['id']}  {item['ip'] or '未知IP':<16}"
                f"  最近活动 {_fmt(item['last_seen'])}"
            )
        if history:
            print("最近登录记录:")
            for row in history:
                mark = "成功" if row["ok"] else "失败"
                print(
                    f"  - {_fmt(row['created_at'])}  {mark}"
                    f"  {row['ip'] or '未知IP':<16}  {row['detail']}"
                )
        return 0
    finally:
        store.close()


def cmd_logout_all(args: argparse.Namespace) -> int:
    store = Store(args.data_dir)
    try:
        removed = store.clear_sessions()
        store.log("auth", "session", True, f"通过 CLI 下线全部会话 {removed} 个")
        print(f"已下线 {removed} 个会话")
        return 0
    finally:
        store.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m aws_helper.cli",
        description="AWS 小助手管理命令（密码重置、状态查看）",
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help=f"数据目录，默认 {default_dir()}（也可用 AWS_HELPER_DATA 环境变量）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    reset = sub.add_parser("reset-password", help="重置面板登录密码")
    reset.add_argument("--password", help="指定新密码，省略则生成随机强密码")
    reset.add_argument(
        "--force", action="store_true", help="允许使用不满足强度要求的密码"
    )
    reset.set_defaults(func=cmd_reset_password)

    status = sub.add_parser("status", help="查看密码、会话和登录记录")
    status.set_defaults(func=cmd_status)

    logout = sub.add_parser("logout-all", help="下线所有登录会话")
    logout.set_defaults(func=cmd_logout_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
