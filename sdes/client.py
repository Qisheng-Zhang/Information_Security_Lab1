"""第 3 关: TCP Socket 加密通信演示 —— 客户端。

运行::

    python -m sdes.client                       # 默认连接 127.0.0.1:50007
    python -m sdes.client --port 60000
    python -m sdes.client --key 0000011111
    python -m sdes.client -m "信息安全导论"     # 直接发送一条明文
    python -m sdes.client --interactive          # 进入交互模式

工作原理
--------
客户端负责**加密**, 服务端负责**解密**, 构成一条真实的加密通信链路::

    [本地] 明文 --S-DES(密钥K)--> 密文(16进制) --TCP--> [服务端] --S-DES解密--> 明文

加密与解密都在本地/对端用同一份 ``sdes.core`` 完成, 但网络上传输的只有
密文, 明文不会出现在 TCP 报文中。

不带 ``-m`` / ``-i`` 时, 客户端会跑一遍自动化演示:
发送若干条测试明文 (含中文与需要补位的长度), 打印每一步的
明文 / 密文 / 服务端回显, 并校验服务端回显与本地原文一致。
"""

from __future__ import annotations

import argparse
import socket
import sys

from . import codec
from .core import KEY_BITS
from .server import (
    DEFAULT_HOST,
    DEFAULT_KEY,
    DEFAULT_PORT,
    _check_key,
    _escape,
    _unescape,
)

DEMO_MESSAGES = [
    "This is a test",
    "信息安全导论",
    "A",
    "Hello, S-DES! 1234567890",
]


class SDesClient:
    """与 S-DES 服务端对话的简单客户端。"""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 key: str = DEFAULT_KEY, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.key = _check_key(key)
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.fp = None

    # -- 连接管理 ---------------------------------------------------------
    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self.fp = self.sock.makefile("rwb")

    def close(self) -> None:
        try:
            if self.fp is not None:
                self.fp.close()
        finally:
            if self.sock is not None:
                self.sock.close()
        self.fp = None
        self.sock = None

    def __enter__(self) -> "SDesClient":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- 协议交互 ---------------------------------------------------------
    def _request(self, line: str) -> str:
        if self.fp is None:
            raise RuntimeError("尚未连接, 请先调用 connect()")
        self.fp.write((line + "\n").encode("utf-8"))
        self.fp.flush()
        reply = self.fp.readline()
        if not reply:
            raise ConnectionError("服务端已关闭连接")
        return reply.decode("utf-8").strip()

    def ping(self) -> str:
        return self._request("PING")

    def server_key(self) -> str:
        return self._request("KEY")

    def encrypt(self, plaintext: str, key: str | None = None) -> str:
        """把明文交给服务端加密, 返回密文 16 进制串。

        明文可以包含空格 (例如 ``This is a test``), 服务端会把命令之后
        的整段文本当作载荷。若显式传入的 ``key`` 不是合法的 10-bit 密钥,
        会在本地直接抛出 ``ValueError``; 服务端若返回 ``ERR ...`` 也抛出
        ``ValueError``, 避免把错误文本误当作密文继续参与后续运算。

        明文里的换行/回车会先用 ``\\n``/``\\r`` 转义再上线, 以免破坏
        "一行一条命令"的文本协议; 服务端解密出明文后再做同样的转义回写,
        客户端在 :meth:`decrypt` 里还原。
        """
        if key is not None:
            key = _check_key(key)
        wire = _escape(plaintext)
        reply = self._request(
            f"ENC {wire}" if key is None else f"ENC {key} {wire}"
        )
        if reply.startswith("ERR "):
            raise ValueError(reply[4:])
        return reply

    def decrypt(self, ciphertext_hex: str, key: str | None = None) -> str:
        """把密文交给服务端解密, 返回明文。"""
        if key is not None:
            key = _check_key(key)
        cmd = f"DEC {ciphertext_hex}" if key is None else f"DEC {key} {ciphertext_hex}"
        reply = self._request(cmd)
        if reply.startswith("ERR "):
            raise ValueError(reply[4:])
        return _unescape(reply)

    # -- 第 3 关主流程 ----------------------------------------------------
    def send_message(self, message: str, verbose: bool = True) -> dict:
        """本地加密 -> 服务端解密 -> 校验是否还原。

        返回 ``{"plaintext", "ciphertext_hex", "server_plaintext", "ok"}``。
        """
        ct = codec.encrypt_text_hex(message, self.key)
        echo = self.decrypt(ct)
        result = {
            "plaintext": message,
            "ciphertext_hex": ct,
            "server_plaintext": echo,
            "ok": echo == message,
        }
        if verbose:
            print(f"  明文 (本地)      : {message!r}")
            print(f"  密文 (线上传输)  : {ct}")
            print(f"  服务端解出明文   : {echo!r}")
            print(f"  校验             : {'成功 ✓' if result['ok'] else '失败 ✗'}")
        return result


def demo(host: str, port: int, key: str) -> int:
    """自动化演示: 依次发送 DEMO_MESSAGES, 汇总校验结果。"""
    print(f"连接服务端 {host}:{port} …")
    with SDesClient(host, port, key) as client:
        print(f"  握手 PING -> {client.ping()}")
        print(f"  服务端密钥 -> {client.server_key()}")
        print(f"  本地密钥   -> {key}\n")

        results = []
        for i, message in enumerate(DEMO_MESSAGES, 1):
            print(f"[{i}/{len(DEMO_MESSAGES)}] 发送 {message!r}")
            results.append(client.send_message(message))
            print()

        good = sum(1 for r in results if r["ok"])
        print("=" * 58)
        print(f"演示完成: {good}/{len(results)} 条消息成功往返")
        if good != len(results):
            print("[!] 存在校验失败的条目, 请检查双方密钥是否一致。", file=sys.stderr)
            return 1
        print("结论: 客户端加密的密文, 经 TCP 传输后由服务端正确解密还原。")
        return 0


def interactive(host: str, port: int, key: str) -> int:
    """交互模式: 逐行输入明文, 打印密文与服务端解密结果。"""
    with SDesClient(host, port, key) as client:
        print(f"已连接 {host}:{port} (密钥 {key})。输入明文后回车, 空行或 quit 退出。")
        while True:
            try:
                message = input("明文> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not message or message.lower() in ("quit", "exit"):
                break
            client.send_message(message)
            print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sdes.client",
        description="S-DES TCP 加密通信客户端 (作业第 3 关)",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"服务端地址 (默认 {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"服务端端口 (默认 {DEFAULT_PORT})")
    parser.add_argument("--key", default=DEFAULT_KEY, help=f"10-bit 密钥 (默认 {DEFAULT_KEY})")
    parser.add_argument("-m", "--message", help="只发送一条明文后退出")
    parser.add_argument("-i", "--interactive", action="store_true", help="进入交互模式")
    parser.add_argument("--raw", action="store_true", help="只打印服务端应答, 不打印说明")
    args = parser.parse_args(argv)

    try:
        if args.message is not None:
            with SDesClient(args.host, args.port, args.key) as client:
                result = client.send_message(args.message, verbose=not args.raw)
            return 0 if result["ok"] else 1
        if args.interactive:
            return interactive(args.host, args.port, args.key)
        return demo(args.host, args.port, args.key)
    except (OSError, ConnectionError) as exc:
        print(f"[!] 无法连接 {args.host}:{args.port} —— {exc}", file=sys.stderr)
        print("    请先在另一个终端启动服务端: python -m sdes.server", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
