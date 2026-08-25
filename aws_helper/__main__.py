"""启动入口：python -m aws_helper"""

from __future__ import annotations

import argparse
import os


def main() -> None:
    parser = argparse.ArgumentParser(prog="aws-helper", description="AWS 小助手 Web 面板")
    parser.add_argument(
        "--host",
        default=os.environ.get("AWS_HELPER_HOST", "127.0.0.1"),
        help="监听地址，默认 127.0.0.1（对外暴露请放到 HTTPS 反代之后）",
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("AWS_HELPER_PORT", "8765"))
    )
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"[警告] 正在监听 {args.host} —— 面板持有你的 AWS 凭据，"
            "务必设置 AWS_HELPER_PASSWORD 并置于 HTTPS 反代之后。"
        )

    import uvicorn

    uvicorn.run("aws_helper.web.app:app", host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
