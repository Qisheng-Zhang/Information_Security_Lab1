# -*- coding: utf-8 -*-
"""S-DES 第 3 关网络往返自测: 在进程内启动 SDesServer (端口 0 由系统分配), 用 SDesClient 完成真实 TCP 通信.

运行 (项目根目录):
    python -m tests.test_network

覆盖点:
  1. PING/KEY 基本连通与密钥回读;
  2. 服务端 ENC 结果 == 本地 codec.encrypt_text_hex 结果 (交叉验证);
  3. 服务端 DEC 结果 == 原始明文 (含中文/UTF-8/换行等需要转义的字符);
  4. 客户端 send_message 往返 ok=True;
  5. 指定密钥重载 (3-token 形式);
  6. 错误处理: 非法密钥返回 ERR 且连接保持可用.
"""
from __future__ import annotations

import socket
import threading

from sdes import codec, core
from sdes.client import SDesClient
from sdes.server import DEFAULT_KEY, SDesServer

_FAILURES: list = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name}  --  {detail}")
        _FAILURES.append(name)


class _LiveServer:
    """进程内服务端: 监听 127.0.0.1:0, 后台线程 serve_forever. 用作上下文管理器."""

    def __init__(self, key: str = DEFAULT_KEY) -> None:
        self.server = SDesServer(("127.0.0.1", 0), key)
        self.host, self.port = self.server.server_address[0], self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_LiveServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def test_transport() -> None:
    print("\n== 第 3 关: TCP Socket 加密通信 ==")
    with _LiveServer() as live:
        with SDesClient(live.host, live.port, DEFAULT_KEY) as cli:
            check("连通: PING -> PONG", cli.ping() == "PONG", f"实际 {cli.ping()!r}")
            check("回读服务端密钥", cli.server_key() == DEFAULT_KEY,
                  f"实际 {cli.server_key()!r}")

            # 2/3. 服务端加解密与本地实现一致
            samples = [
                "This is a test",
                "信息安全导论",
                "A",
                "Hello, S-DES! 1234567890",
                "多行\n文本\r测试",          # 需要 _escape/_unescape 保护
                "反斜杠\\与\\n字面量",
            ]
            ok_enc = ok_dec = True
            detail_enc = detail_dec = ""
            for text in samples:
                ct = cli.encrypt(text)
                local = codec.encrypt_text_hex(text, DEFAULT_KEY)
                if ct != local:
                    ok_enc, detail_enc = False, f"{text!r}: 服务端 {ct} != 本地 {local}"
                back = cli.decrypt(ct)
                if back != text:
                    ok_dec, detail_dec = False, f"{text!r} -> {back!r}"
            check("服务端 ENC 与本地 codec 一致 (6 个样例)", ok_enc, detail_enc)
            check("服务端 DEC 还原明文 (含转义字符)", ok_dec, detail_dec)

            # 4. 往返助手
            res = cli.send_message("This is a test", verbose=False)
            check("send_message 往返 ok",
                  res["ok"] and res["ciphertext_hex"] == codec.encrypt_text_hex("This is a test", DEFAULT_KEY),
                  f"实际 {res}")

            # 5. 指定密钥 (3-token)
            other = "0000011111"
            ct2 = cli.encrypt("secret", other)
            check("指定密钥加解密一致",
                  ct2 == codec.encrypt_text_hex("secret", other) and cli.decrypt(ct2, other) == "secret",
                  f"实际 {ct2!r}")

            # 6. 错误处理不破坏连接
            try:
                cli.encrypt("x", "123")
                raised = False
            except ValueError as exc:
                raised = "密钥" in str(exc)
            check("非法密钥返回 ERR 异常", raised)
            check("出错后连接仍可用", cli.ping() == "PONG", "连接已损坏")

            # 客户端本地加密结果也能被独立 socket 送往服务端解密
            with socket.create_connection((live.host, live.port), timeout=5) as raw:
                fp = raw.makefile("rwb")
                ct3 = codec.encrypt_text_hex("raw socket", DEFAULT_KEY)
                fp.write(f"DEC {ct3}\n".encode("utf-8"))
                fp.flush()
                reply = fp.readline().decode("utf-8").strip()
            check("裸 socket 行协议 DEC 可用", reply == "raw socket", f"实际 {reply!r}")


def test_reference_consistency() -> None:
    """不同密钥下, 服务端 ENC 都应等于本地核心实现 (批量抽取)."""
    print("\n== 第 3 关: 服务端/核心实现一致性 ==")
    keys = ["1010000010", "0000011111", "1111111111", "0000000000", "1100110011"]
    with _LiveServer(keys[0]) as live:
        with SDesClient(live.host, live.port, keys[0]) as cli:
            bad = []
            for k in keys:
                for pt in range(0, 256, 17):
                    plain = "".join(chr(65 + ((pt >> s) & 0x1F) % 26) for s in (0, 2, 4))
                    server_hex = cli.encrypt(plain, k)
                    local_hex = codec.encrypt_text_hex(plain, k)
                    if server_hex != local_hex:
                        bad.append((k, plain, server_hex, local_hex))
            check(f"5 密钥 × {len(range(0, 256, 17))} 明文全部一致", not bad, f"不一致 {bad[:3]}")
            check("core 与 codec 密文长度匹配", len(codec.encrypt_text_hex("abc", keys[0])) == 6,
                  f"实际 {codec.encrypt_text_hex('abc', keys[0])!r}")


def main() -> int:
    print("S-DES 自测套件 —— 第 3 关网络通信")
    test_transport()
    test_reference_consistency()
    print()
    if _FAILURES:
        print(f"结果: {len(_FAILURES)} 项失败")
        for name in _FAILURES:
            print(f"  - {name}")
        return 1
    print("结果: 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
