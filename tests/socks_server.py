"""最小 SOCKS5 服务器，仅用于测试代理链路是否真的被走通。

支持无认证和用户名/密码认证（RFC 1928 / RFC 1929），只实现 CONNECT。
记录每一个被代理的目标地址，测试据此断言流量确实经过了代理。
"""

from __future__ import annotations

import socket
import struct
import threading


class Socks5Server:
    def __init__(self, username: str | None = None, password: str | None = None) -> None:
        self.username = username
        self.password = password
        self.targets: list[tuple[str, int]] = []
        self.auth_failures = 0
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        if self.username:
            return f"socks5h://{self.username}:{self.password}@127.0.0.1:{self.port}"
        return f"socks5h://127.0.0.1:{self.port}"

    def __enter__(self) -> "Socks5Server":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            if not self._handshake(conn):
                return
            target = self._read_request(conn)
            if target is None:
                return
            host, port = target
            self.targets.append((host, port))

            try:
                upstream = socket.create_connection((host, port), timeout=10)
            except OSError:
                conn.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
                return

            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            self._pipe(conn, upstream)
        except OSError:
            pass
        finally:
            for s in (conn, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _handshake(self, conn: socket.socket) -> bool:
        head = _recv_exact(conn, 2)
        if not head or head[0] != 0x05:
            return False
        methods = _recv_exact(conn, head[1]) or b""

        if self.username:
            if 0x02 not in methods:
                conn.sendall(b"\x05\xff")
                return False
            conn.sendall(b"\x05\x02")
            return self._auth(conn)

        conn.sendall(b"\x05\x00")
        return True

    def _auth(self, conn: socket.socket) -> bool:
        ver = _recv_exact(conn, 1)
        if not ver or ver[0] != 0x01:
            return False
        ulen = _recv_exact(conn, 1)
        user = _recv_exact(conn, ulen[0]) if ulen else b""
        plen = _recv_exact(conn, 1)
        pwd = _recv_exact(conn, plen[0]) if plen else b""

        ok = (
            user.decode(errors="replace") == self.username
            and pwd.decode(errors="replace") == self.password
        )
        conn.sendall(b"\x01\x00" if ok else b"\x01\x01")
        if not ok:
            self.auth_failures += 1
        return ok

    def _read_request(self, conn: socket.socket) -> tuple[str, int] | None:
        head = _recv_exact(conn, 4)
        if not head or head[1] != 0x01:
            return None
        atyp = head[3]
        if atyp == 0x01:
            raw = _recv_exact(conn, 4)
            host = socket.inet_ntoa(raw) if raw else ""
        elif atyp == 0x03:
            n = _recv_exact(conn, 1)
            host_raw = _recv_exact(conn, n[0]) if n else b""
            host = host_raw.decode(errors="replace")
        elif atyp == 0x04:
            raw = _recv_exact(conn, 16)
            host = socket.inet_ntop(socket.AF_INET6, raw) if raw else ""
        else:
            return None
        port_raw = _recv_exact(conn, 2)
        if not port_raw:
            return None
        return host, struct.unpack("!H", port_raw)[0]

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        def copy(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=copy, args=(a, b), daemon=True)
        t.start()
        copy(b, a)
        t.join(timeout=5)


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
