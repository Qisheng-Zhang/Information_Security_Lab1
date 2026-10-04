"""S-DES 网页版界面 —— 纯标准库 http.server 后端。

用法::

    python -m sdes.webapp                 # 打开 http://127.0.0.1:8000
    python -m sdes.webapp --port 9000     # 换端口
    python -m sdes.webapp --open          # 启动后自动打开浏览器

设计说明
--------
后端**不做任何算法实现**, 全部计算复用 :mod:`sdes.core` / :mod:`sdes.codec` /
:mod:`sdes.crack` / :mod:`sdes.client`, 所以网页版、tkinter 版、命令行版三者
结果必然一致(这也是第 2 关"交叉测试"的一个直接体现)。

前端静态资源位于 ``sdes/web/`` 目录: ``index.html`` / ``style.css`` / ``app.js``,
由同一个服务进程一并提供, 因此整个网页版**零第三方依赖**(仅 Python 标准库)。

接口一览(全部返回 JSON 对象 ``{"ok": bool, "data": ..., "error": str}``)
------------------------------------------------------------------------
GET  /api/meta              版本、默认参数、规格表
GET  /api/report            第 5 关纯文本碰撞报告
POST /api/encrypt           {plaintext, key}                  -> 密文 + 过程明细
POST /api/decrypt           {ciphertext, key}                 -> 明文
POST /api/text/encrypt      {text, key, encoding}             -> hex 密文
POST /api/text/decrypt      {hex, key, encoding}              -> 原字符串
POST /api/vectors           {count, key?}                     -> 规范化测试向量 + CSV
POST /api/vectors/compare   {csv_a, csv_b}                    -> 比对结果
POST /api/crack             {pairs, threaded, workers, chunk} -> 破解结果
POST /api/collisions        {sample?}                         -> 第 5 关统计摘要
POST /api/tcp/send          {host, port, key, text}           -> 与服务端往返结果
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import codec, core, crack
from .__init__ import __version__

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_KEY = "1010000010"
DEFAULT_PT = "10010111"
VECTOR_SEED = 20261008  # 与 tkinter 版 / 测试向量一致, 保证可复现

_WEB_DIR = Path(__file__).resolve().parent / "web"
_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
}


# ---------------------------------------------------------------------------
# 各接口的纯计算函数(可单独测试)
# ---------------------------------------------------------------------------

def api_meta(_payload: dict) -> dict:
    """版本与规格常量, 供前端渲染页眉/规格表。"""
    return {
        "version": __version__,
        "default_key": DEFAULT_KEY,
        "default_plaintext": DEFAULT_PT,
        "default_host": DEFAULT_HOST,
        "default_port": 50007,      # 第 3 关 TCP 服务端端口(与 server.py 一致)
        "block_bits": core.BLOCK_BITS,
        "key_bits": core.KEY_BITS,
        "tables": {
            "P10": list(core.P10),
            "P8": list(core.P8),
            "IP": list(core.IP),
            "IP_INV": list(core.IP_INV),
            "EP": list(core.EP),
            "SPBOX": list(core.SPBOX),
            "SBOX1": [list(r) for r in core.SBOX1],
            "SBOX2": [list(r) for r in core.SBOX2],
        },
        "note": "本作业 SBox2 与标准 S-DES 的 S1 不同, 因此公开标准测试向量不能作为期望密文。",
    }


def api_encrypt(payload: dict) -> dict:
    """单个 8-bit 分组加密, 同时返回逐步中间状态。"""
    pt = _bits(payload.get("plaintext"), core.BLOCK_BITS, "明文")
    key = _bits(payload.get("key"), core.KEY_BITS, "密钥")
    ct = core.encrypt(pt, key)
    k1, k2 = core.key_schedule(key)
    return {
        "plaintext": pt,
        "key": key,
        "ciphertext": ct,
        "ciphertext_hex": format(int(ct, 2), "02X"),
        "k1": core.int_to_bits(k1, 8),
        "k2": core.int_to_bits(k2, 8),
        "steps": core.trace(pt, key),
    }


def api_decrypt(payload: dict) -> dict:
    """单个 8-bit 分组解密。"""
    ct = _bits(payload.get("ciphertext"), core.BLOCK_BITS, "密文")
    key = _bits(payload.get("key"), core.KEY_BITS, "密钥")
    pt = core.decrypt(ct, key)
    k1, k2 = core.key_schedule(key)
    return {
        "ciphertext": ct,
        "key": key,
        "plaintext": pt,
        "plaintext_hex": format(int(pt, 2), "02X"),
        "k1": core.int_to_bits(k1, 8),
        "k2": core.int_to_bits(k2, 8),
    }


def api_text_encrypt(payload: dict) -> dict:
    """字符串 -> 按 1 Byte 分组加密 -> hex 密文 (第 3 关)。"""
    text = payload.get("text")
    if not isinstance(text, str):
        raise ValueError("缺少 text 字段")
    key = _bits(payload.get("key"), core.KEY_BITS, "密钥")
    encoding = payload.get("encoding") or "utf-8"
    hexstr = codec.encrypt_text_hex(text, key, encoding)
    bits = codec.text_to_bits(text, encoding)
    data = text.encode(encoding)
    return {
        "text": text,
        "key": key,
        "encoding": encoding,
        "ciphertext_hex": hexstr,
        "plaintext_bits": bits,
        "byte_count": len(data),
        "block_count": len(data),
        "padded_bits": -len(bits) % 8,
    }


def api_text_decrypt(payload: dict) -> dict:
    """hex 密文 -> 字符串 (第 3 关)。"""
    hexstr = _clean(payload.get("hex") or "")
    if not hexstr:
        raise ValueError("密文不能为空")
    if len(hexstr) % 2 != 0 or any(c not in "0123456789abcdefABCDEF" for c in hexstr):
        raise ValueError("密文必须是偶数长度的十六进制字符串")
    key = _bits(payload.get("key"), core.KEY_BITS, "密钥")
    encoding = payload.get("encoding") or "utf-8"
    return {
        "hex": hexstr.upper(),
        "key": key,
        "encoding": encoding,
        "text": codec.decrypt_hex_text(hexstr, key, encoding),
    }


def api_vectors(payload: dict) -> dict:
    """生成规范化测试向量(第 2 关), 固定随机种子保证可复现。"""
    raw_count = payload.get("count")
    if raw_count in (None, ""):
        raw_count = 200
    try:
        count = int(raw_count)
    except (TypeError, ValueError):
        raise ValueError("条数必须是整数")
    if not 1 <= count <= 5000:
        raise ValueError("条数需在 1~5000 之间")

    fixed_key = payload.get("key")
    fixed_key = _bits(fixed_key, core.KEY_BITS, "密钥") if fixed_key else None

    rng = random.Random(VECTOR_SEED)
    rows = []
    for _ in range(count):
        p = rng.randrange(1 << core.BLOCK_BITS)
        k = fixed_key or core.int_to_bits(rng.randrange(1 << core.KEY_BITS), core.KEY_BITS)
        c = core.encrypt(core.int_to_bits(p, core.BLOCK_BITS), k)
        rows.append({"pt": core.int_to_bits(p, core.BLOCK_BITS), "key": k, "ct": c})
    csv = "pt,key,ct\n" + "\n".join(f"{r['pt']},{r['key']},{r['ct']}" for r in rows)
    return {"count": count, "seed": VECTOR_SEED, "rows": rows, "csv": csv}


def api_vectors_compare(payload: dict) -> dict:
    """比对两份 CSV 测试向量是否逐行一致(第 2 关交叉测试)。"""
    a = _parse_vector_csv(payload.get("csv_a"), "本机")
    b = _parse_vector_csv(payload.get("csv_b"), "对方")
    total = max(len(a), len(b))
    entries_a = {tuple(r) for r in a}
    entries_b = {tuple(r) for r in b}
    mismatches = [
        {"index": i + 1, "local": list(ra) if i < len(a) else None,
         "remote": list(rb) if i < len(b) else None}
        for i, (ra, rb) in enumerate(zip(a, b)) if ra != rb
    ][:20]
    # 差异条数按「逐行位置」统计: 随机的测试向量允许出现重复行
    # (例如 200 条里恰好有两行完全相同), 若改用集合差集会把这种
    # 无害的重复误报成差异, 因此这里只做严格的位置比较。
    positional = sum(1 for ra, rb in zip(a, b) if ra != rb)
    mismatch_count = positional + abs(len(a) - len(b))
    return {
        "local_rows": len(a),
        "remote_rows": len(b),
        "same": len(a) == len(b) and entries_a == entries_b and positional == 0,
        "same_set": entries_a == entries_b,
        "total": total,
        "mismatch_count": mismatch_count,
        "mismatches": mismatches,
    }


def api_crack(payload: dict) -> dict:
    """第 4 关: 由明文-密文对穷举 10-bit 密钥。"""
    raw = payload.get("pairs") or []
    if not isinstance(raw, list) or not raw:
        raise ValueError("至少需要一个明文-密文对")
    pairs = []
    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValueError("每个明密文对格式应为 [明文, 密文]")
        pairs.append((
            _bits(item[0], core.BLOCK_BITS, "明文"),
            _bits(item[1], core.BLOCK_BITS, "密文"),
        ))

    threaded = bool(payload.get("threaded", True))
    try:
        workers = int(payload.get("workers") or 8)
        chunk = int(payload.get("chunk") or 64)
    except (TypeError, ValueError):
        raise ValueError("线程数 / 每块大小必须是整数")
    workers = max(1, min(workers, 64))
    chunk = max(1, min(chunk, 1024))

    if threaded:
        result = crack.brute_force_threaded(pairs, workers=workers, chunk=chunk)
    else:
        result = crack.brute_force(pairs)
    return {
        "keys": [core.int_to_bits(k, core.KEY_BITS) for k in result["keys"]],
        "key_count": len(result["keys"]),
        "tried": result["tried"],
        "elapsed_ms": result["elapsed"] * 1000.0,
        "rate": result["rate"],
        "workers": result.get("workers"),
        "chunks": result.get("chunks"),
        "threaded": threaded,
        "pair_count": len(pairs),
    }


def api_collisions(payload: dict) -> dict:
    """第 5 关: 枚举 1024x256 统计碰撞(完整表太大, 返回摘要 + 指定明文的样例)。"""
    try:
        sample_pt = int(payload.get("sample") or 0)
    except (TypeError, ValueError):
        raise ValueError("样例明文必须是 0~255 的整数")
    if not 0 <= sample_pt < (1 << core.BLOCK_BITS):
        raise ValueError("样例明文必须是 0~255 的整数")

    stats = crack.analyze_collisions()
    row = stats["table"].get(sample_pt, {})
    multi = [(ct, keys) for ct, keys in row.items() if len(keys) > 1]
    multi.sort(key=lambda kv: (-len(kv[1]), kv[0]))
    avg_candidates = sum(v["avg_keys_per_cipher"] for v in stats["per_plaintext"].values()) / len(stats["per_plaintext"])
    return {
        "key_space": crack._KEY_SPACE,
        "block_space": crack._BLOCK_SPACE,
        "total_pairs": stats["total_pairs"],
        "max_bucket": stats["max_bucket"],
        "distinct_per_pt": stats["distinct_per_pt"],
        "avg_candidates_per_cipher": avg_candidates,
        "buckets": [{"size": s, "count": stats["buckets"][s]} for s in sorted(stats["buckets"])],
        "equivalent_classes": len(crack.equivalent_key_classes()),
        "sample": {
            "plaintext": core.int_to_bits(sample_pt, core.BLOCK_BITS),
            "multi_cipher_count": len(multi),
            "cases": [
                {"ct": core.int_to_bits(ct, core.BLOCK_BITS),
                 "keys": [core.int_to_bits(k, core.KEY_BITS) for k in keys]}
                for ct, keys in multi[:8]
            ],
        },
    }


def api_report(_payload: dict) -> dict:
    """第 5 关纯文本报告。"""
    return {"text": crack.collision_report(0)}


def api_tcp_send(payload: dict) -> dict:
    """第 3 关: 通过 TCP 把密文发给 sdes.server 并取回解密结果。"""
    from .client import SDesClient
    text = payload.get("text")
    if not isinstance(text, str) or text == "":
        raise ValueError("发送内容不能为空")
    host = payload.get("host") or DEFAULT_HOST
    try:
        port = int(payload.get("port") or 50007)
    except (TypeError, ValueError):
        raise ValueError("端口必须是整数")
    key = _bits(payload.get("key"), core.KEY_BITS, "密钥")

    log = []
    ciphertext_hex = codec.encrypt_text_hex(text, key)
    log.append(f"① 本地加密: “{text}” --S-DES--> {ciphertext_hex}")
    with SDesClient(host=host, port=port, key=key) as client:
        pong = client.ping()
        log.append(f"② 连接 {host}:{port}  PING -> {pong}")
        reply = client.decrypt(ciphertext_hex)
        log.append(f"③ 发送 DEC {ciphertext_hex}")
        log.append(f"④ 服务端解密回显: “{reply}”")
        server_key = client.server_key()
        log.append(f"⑤ 服务端当前密钥: {server_key}")
    ok = reply == text
    log.append("⑥ 校验: 回显与原文一致 ✓" if ok
               else "⑥ 校验: 回显与原文不一致 ✗ (请确认两侧密钥相同)")
    return {
        "text": text,
        "ciphertext_hex": ciphertext_hex,
        "server_plaintext": reply,
        "server_key": server_key,
        "host": host,
        "port": port,
        "ok": ok,
        "log": log,
    }


# ---------------------------------------------------------------------------
# 参数校验 / 解析辅助
# ---------------------------------------------------------------------------

def _clean(text) -> str:
    """去掉空白与下划线, 便于粘贴带分隔符的位串。"""
    return "".join(str(text).split()).replace("_", "")


def _bits(value, width: int, label: str) -> str:
    """校验 value 是 width 位 0/1 串并返回。"""
    if not value:
        raise ValueError(f"{label}不能为空")
    s = _clean(value)
    if len(s) != width:
        raise ValueError(f"{label}必须是 {width} bit, 当前 {len(s)} bit")
    if set(s) - set("01"):
        raise ValueError(f"{label}只能包含 0 和 1")
    return s


def _parse_vector_csv(text, who: str) -> list:
    """解析 pt,key,ct 三列 CSV(允许 BOM / 空行 / 表头)。"""
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"{who}的 CSV 内容为空")
    rows = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip().lstrip("\ufeff")
        if not line or line.lower().startswith("pt,"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            raise ValueError(f"{who}的 CSV 第 {len(rows) + 1} 行格式错误: {line!r}")
        rows.append((parts[0], parts[1], parts[2]))
    if not rows:
        raise ValueError(f"{who}的 CSV 没有有效数据行")
    return rows


# ---------------------------------------------------------------------------
# HTTP 处理
# ---------------------------------------------------------------------------

_GET_ROUTES = {
    "/api/meta": api_meta,
    "/api/report": api_report,
}
_POST_ROUTES = {
    "/api/encrypt": api_encrypt,
    "/api/decrypt": api_decrypt,
    "/api/text/encrypt": api_text_encrypt,
    "/api/text/decrypt": api_text_decrypt,
    "/api/vectors": api_vectors,
    "/api/vectors/compare": api_vectors_compare,
    "/api/crack": api_crack,
    "/api/collisions": api_collisions,
    "/api/tcp/send": api_tcp_send,
}


class SDesWebHandler(BaseHTTPRequestHandler):
    """静态资源 + JSON API 处理器。"""

    server_version = f"SDesWeb/{__version__}"
    protocol_version = "HTTP/1.1"

    # -- 日志 --------------------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: A003 - 覆盖基类命名
        sys.stderr.write(f"[web] {self.address_string()} {fmt % args}\n")

    # -- 响应辅助 ----------------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, obj: dict, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"请求体不是合法 JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return payload

    # -- 路由 --------------------------------------------------------------
    def do_GET(self):  # noqa: N802 - 基类约定
        path = urlparse(self.path).path
        handler = _GET_ROUTES.get(path)
        if handler is not None:
            self._invoke(handler, {})
            return
        self._serve_static(path)

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        handler = _POST_ROUTES.get(path)
        if handler is None:
            self._send_json({"ok": False, "error": f"未知接口: {path}"}, 404)
            return
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
            return
        self._invoke(handler, payload)

    def _invoke(self, handler, payload: dict) -> None:
        try:
            data = handler(payload)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
        except ConnectionRefusedError:
            self._send_json({"ok": False,
                             "error": "连接被拒绝: 请先运行 python -m sdes.server 启动服务端"}, 502)
        except OSError as exc:
            self._send_json({"ok": False, "error": f"网络错误: {exc}"}, 502)
        except Exception as exc:  # 兜底, 避免线程崩溃
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 500)
        else:
            self._send_json({"ok": True, "data": data})

    def _serve_static(self, path: str) -> None:
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (_WEB_DIR / rel).resolve()
        if _WEB_DIR.resolve() not in target.parents and target != _WEB_DIR.resolve():
            self._send(403, "403 Forbidden".encode("utf-8"), "text/plain; charset=utf-8")
            return
        if not target.is_file():
            self._send(404, "404 Not Found".encode("utf-8"), "text/plain; charset=utf-8")
            return
        ctype = _MIME.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)


class SDesWebServer(ThreadingHTTPServer):
    """线程化的本地网页服务。"""

    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
          open_browser: bool = False) -> None:
    """启动网页版界面, 阻塞运行直到 Ctrl+C。"""
    if not _WEB_DIR.is_dir():
        raise SystemExit(f"[!] 找不到前端目录: {_WEB_DIR}")
    httpd = SDesWebServer((host, port), SDesWebHandler)
    url = f"http://{host}:{port}/"
    print("=" * 66)
    print("  S-DES 网页版界面 —— 信息安全导论 作业1")
    print("=" * 66)
    print(f"  访问地址: {url}")
    print(f"  前端目录: {_WEB_DIR}")
    print("  Ctrl+C 结束服务")
    print("=" * 66)
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] 正在关闭 ...")
    finally:
        httpd.server_close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sdes.webapp",
        description="S-DES 网页版界面 (纯 Python 标准库, 无第三方依赖)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="监听地址, 默认 127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="监听端口, 默认 8000")
    parser.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    args = parser.parse_args(argv)

    try:
        serve(args.host, args.port, args.open)
    except OSError as exc:
        print(f"[!] 无法监听 {args.host}:{args.port} —— {exc}")
        print("    端口可能被占用, 换一个: python -m sdes.webapp --port 8080")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
