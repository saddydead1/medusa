"""Минимальный SOCKS5 сервер для проверок: он только переключает TCP на адрес получателя.

Нужен тестам панели: панель обязана уметь дойти до API ноды через socks5 (нода за NAT или
доступна только через прыжок). Реализация сознательно маленькая: только CONNECT, только IPv4 —
панель ходит по адресам нод и HTTP, ей не нужен UDP BIND.

Сервер ведёт журнал `connections` — по нему тест и проверяет, что поход к ноде прошёл через
прокси, а не мимо него.
"""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field

REPLY_OK = b"\x05\x00\x00\x01" + bytes(6)          # IPv4 0.0.0.0:0 — клиенту всё равно
REPLY_REFUSED = b"\x05\x07\x00\x01" + bytes(6)     # command not supported
REPLY_HOST_DOWN = b"\x05\x01\x00\x01" + bytes(6)   # host unreachable


@dataclass
class Socks5Proxy:
    """SOCKS5-прокси в фоновой нити. `start()` -> (host, port), `.url()` -> socks5://..."""

    host: str = "127.0.0.1"
    port: int = 0                       # 0 — свободный порт от ОС
    username: str | None = None
    password: str | None = None
    connections: list[str] = field(default_factory=list)
    fail_next: bool = False             # следующий запрос оборвать: проверка «прокси сломан»
    _server: socket.socket | None = None
    _thread: threading.Thread | None = None

    def start(self) -> tuple[str, int]:
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(16)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self.host, self.port

    def url(self) -> str:
        auth = ""
        if self.username is not None:
            auth = f"{self.username}:{self.password}@"
        return f"socks5://{auth}{self.host}:{self.port}"

    def stop(self) -> None:
        if self._server is not None:
            self._server.close()

    # ---------- внутреннее ----------

    def _serve(self) -> None:
        assert self._server is not None
        while True:
            try:
                client, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _read_exact(self, sock: socket.socket, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise OSError("обрвано")
            data += chunk
        return data

    def _handle(self, client: socket.socket) -> None:
        with client:
            try:
                greeting = self._read_exact(client, 2)
                if greeting[0] != 0x05:
                    return
                methods = self._read_exact(client, greeting[1])

                if self.username is not None:
                    if 0x02 not in methods:
                        client.sendall(b"\x05\xff")
                        return
                    client.sendall(b"\x05\x02")                       # выбираем username/password
                    handshake = self._read_exact(client, 2)
                    user = self._read_exact(client, handshake[1])
                    password = self._read_exact(client, self._read_exact(client, 1)[0])
                    passed = (handshake[0] == 0x01
                              and user.decode() == self.username
                              and password.decode() == (self.password or ""))
                    # RFC1929 (и socksio так же): ответ — VER + STATUS, успех это 0x01 0x00
                    client.sendall(b"\x01\x00" if passed else b"\x01\x01")
                    if not passed:
                        return
                else:
                    if 0x00 not in methods:
                        client.sendall(b"\x05\xff")
                        return
                    client.sendall(b"\x05\x00")

                head = self._read_exact(client, 4)
                if head[1] != 0x01:                                   # умеем только CONNECT
                    client.sendall(REPLY_REFUSED)
                    return
                if head[3] == 0x01:
                    target_host = socket.inet_ntoa(self._read_exact(client, 4))
                elif head[3] == 0x03:
                    target_host = self._read_exact(client, self._read_exact(client, 1)[0]).decode()
                else:
                    client.sendall(REPLY_REFUSED)
                    return
                target_port = int.from_bytes(self._read_exact(client, 2), "big")
                self.connections.append(f"{target_host}:{target_port}")

                if self.fail_next:
                    self.fail_next = False
                    client.sendall(REPLY_HOST_DOWN)
                    return

                try:
                    upstream = socket.create_connection((target_host, target_port), timeout=10)
                except OSError:
                    client.sendall(REPLY_HOST_DOWN)
                    return
                client.sendall(REPLY_OK)
                self._pump(client, upstream)
            except OSError:
                return

    @staticmethod
    def _pump(client: socket.socket, upstream: socket.socket) -> None:
        def pipe(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        a = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
        b = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
        a.start()
        b.start()
        a.join(timeout=30)
        upstream.close()


def _cli() -> int:
    """Запуск настоящего socks5-прокси отдельным процессом: `.venv/bin/python tools/socks5.py
    [user [password]]`. Строку `socks5://...` печатает на stdout — её читает tools/ui_test.mjs,
    чтобы вписать прокси в окно ноды как это сделал бы человек.
    """
    import sys
    args = sys.argv[1:]
    username = args[0] if args else None
    password = args[1] if len(args) > 1 else (username or "medusa")
    proxy = Socks5Proxy(username=username, password=password if username else None)
    proxy.start()
    print(proxy.url(), flush=True)
    try:
        proxy._thread.join()
    except KeyboardInterrupt:
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
