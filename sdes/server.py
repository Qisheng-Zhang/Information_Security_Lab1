"""第 3 关: TCP Socket 加密通信演示 —— 服务端。

运行::

    python -m sdes.server                   # 监听 127.0.0.1:50007
    python -m sdes.server --port 60000      # 指定端口
    python -m sdes.server --key 0000011111  # 指定 10-bit 密钥

行文本协议 (每行一条命令, UTF-8 编码, ``\n`` 结尾)
--------------------------------------------------
``PING``
    心跳, 返回 ``PONG``。
``KEY``
    返回服务端当前使用的 10-bit 密钥。
``ENC <明文>``
    服务端对明文做 S-DES 加密, 返回 16 进制密文。
    明文**可以包含空格**, 命令之后的整段内容都视为明文。
``ENC <密钥> <明文>``
    使用本次指定的密钥加密。
``DEC <密文16进制>``
    服务端对密文做 S-DES 解密, 返回明文 (换行被转义为 ``\\n``)。
``DEC <密钥> <密文16进制>``
    使用本次指定的密钥解密。

参数解析规则: 命令后如果首个 token 恰为合法的 10-bit 密钥且其后仍有内容,
则视为"指定密钥"写法, 否则整段剩余内容都作为载荷 (因此明文/密文允许含空格)。
``QUIT``
    结束本次连接, 返回 ``BYE``。

任何出错都返回 ``ERR <原因>``, 不会中断连接。
每个 TCP 连接由独立线程处理 (``ThreadingTCPServer``), 因此可以同时
服务多个客户端。
"""

from __future__ import annotations

import argparse
import socketserver
import sys

from . import codec
from .core import KEY_BITS

DEFAULT_KEY = "1010000010"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 50007


def _escape(text: str) -> str:
    """把明文压缩到单行, 保证行协议不被换行破坏。"""
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def _unescape(text: str) -> str:
    """``_escape`` 的逆操作 (供客户端使用)。"""
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "r":
                out.append("\r")
                i += 2
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _check_key(key: str) -> str:
    if len(key) != KEY_BITS or set(key) - set("01"):
        raise ValueError(f"密钥必须是 {KEY_BITS} 个 0/1 字符: {key!r}")
    return key


def _is_key(token: str) -> bool:
    """判断一个 token 是否形如 10-bit 密钥 (全 0/1 且长度为 KEY_BITS)。"""
    return len(token) == KEY_BITS and not (set(token) - set("01"))


def _parse_payload(rest: str, default_key: str) -> tuple[str, str]:
    """把 ``ENC``/``DEC`` 的参数部分解析成 ``(密钥, 载荷)``。

    支持两种写法::

        <载荷>              # 使用服务端默认密钥 (载荷可以含空格)
        <密钥> <载荷>       # 使用本次指定的 10-bit 密钥

    因为明文本身可能含空格 (例如 ``This is a test``), 这里**不能**简单地
    按空白切分。解析规则: 只有当剩余部分的首个 token 恰好是合法的
    10-bit 密钥, 且其后面还有非空内容时, 才视为"指定密钥"写法; 否则整段
    剩余部分都当作载荷。

    .. note::
       由此带来的唯一歧义: 若默认密钥模式下, 明文本身以 ``<10个0/1>+空格``
       开头 (例如 ``1010000010 hello``), 会被误判为"指定密钥"写法。此时请
       显式写出密钥, 即发送 ``ENC <密钥> <明文>``。
    """
    body = rest.strip()
    if not body:
        raise ValueError("参数个数错误, 用法: ENC <明文> | ENC <密钥> <明文>")

    first, sep, remainder = body.partition(" ")
    if sep and remainder.strip() and _is_key(first):
        return _check_key(first), remainder.strip()
    return default_key, body


def dispatch(line: str, default_key: str) -> str:
    """处理一条命令, 返回一行应答 (不含换行)。"""
    cmd_token, _, rest = line.partition(" ")
    cmd = cmd_token.strip().upper()
    if not cmd:
        return "ERR 空命令"

    try:
        if cmd == "PING":
            return "PONG"
        if cmd == "KEY":
            return default_key
        if cmd == "QUIT":
            return "BYE"
        if cmd not in ("ENC", "DEC"):
            return f"ERR 未知命令: {cmd} (可用: PING/KEY/ENC/DEC/QUIT)"

        key, payload = _parse_payload(rest, default_key)

        if cmd == "ENC":
            return codec.encrypt_text_hex(_unescape(payload), key)
        return _escape(codec.decrypt_hex_text(payload, key))
    except Exception as exc:  # noqa: BLE001 - 协议层需把任何异常变成 ERR 行
        return f"ERR {exc}"


class SDesHandler(socketserver.StreamRequestHandler):
    """每个连接的会话处理: 逐行读命令, 逐行回应答。"""

    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[+] 连接建立 {peer} (密钥 {self.server.key})", flush=True)
        count = 0
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            reply = dispatch(line, self.server.key)
            self.wfile.write((reply + "\n").encode("utf-8"))
            self.wfile.flush()
            count += 1
            shown = line if len(line) <= 60 else line[:57] + "..."
            print(f"    {peer} > {shown}", flush=True)
            print(f"    {peer} < {reply[:60]}", flush=True)
            if line.split()[0].upper() == "QUIT":
                break
        print(f"[-] 连接关闭 {peer} (共处理 {count} 条命令)", flush=True)


class SDesServer(socketserver.ThreadingTCPServer):
    """可复用的多线程 TCP 服务器。"""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, key: str = DEFAULT_KEY):
        self.key = _check_key(key)
        super().__init__(address, SDesHandler)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, key: str = DEFAULT_KEY) -> None:
    """启动服务端并阻塞, 直到 Ctrl+C。"""
    with SDesServer((host, port), key) as server:
        print("=" * 58)
        print("  S-DES TCP 加密通信服务端 (第 3 关)")
        print(f"  监听地址: {host}:{port}")
        print(f"  当前密钥: {key}")
        print("  协议: ENC <明文> / DEC <密文16进制> / PING / KEY / QUIT")
        print("  停止: Ctrl+C")
        print("=" * 58, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] 收到 Ctrl+C, 正在关闭…", flush=True)
    print("[*] 服务端已停止。", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sdes.server",
        description="S-DES TCP 加密通信服务端 (作业第 3 关)",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"监听地址 (默认 {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"监听端口 (默认 {DEFAULT_PORT})")
    parser.add_argument("--key", default=DEFAULT_KEY, help=f"10-bit 密钥 (默认 {DEFAULT_KEY})")
    args = parser.parse_args(argv)

    try:
        serve(args.host, args.port, args.key)
    except OSError as exc:
        print(f"[!] 无法监听 {args.host}:{args.port} —— {exc}", file=sys.stderr)
        print("    端口可能已被占用, 可换一个: python -m sdes.server --port 50008", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
