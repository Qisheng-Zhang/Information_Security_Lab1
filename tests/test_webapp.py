"""第 6 关(附加): 网页版界面 self-test。

不依赖真实浏览器, 直接在进程内起一个 :class:`sdes.webapp.SDesWebServer`
(端口 0, 由系统分配空闲端口), 然后用 ``urllib`` 走真实的 HTTP 请求验证:

* 静态资源 (``/`` ``/style.css`` ``/app.js``) 能正确返回;
* 目录穿越被拒绝;
* 全部 JSON 接口在正常输入下返回 ``ok=True``, 且结果与直接调用
  :mod:`sdes.core` / :mod:`sdes.codec` / :mod:`sdes.crack` 完全一致
  (保证网页版与命令行版、tkinter 版结果统一, 即第 2 关“交叉测试”的延伸);
* 非法输入返回 HTTP 400 与中文错误原因, 而不是抛栈崩溃。

运行::

    python -m tests.test_webapp
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from sdes import codec, core, crack, webapp


_FAILURES: list = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    """与其它测试模块保持一致的断言记录风格。"""
    tag = "[PASS]" if condition else "[FAIL]"
    print(f"{tag} {name}" + (f"  --  {detail}" if detail else ""))
    if not condition:
        _FAILURES.append(name)
    return condition


class _LiveWeb:
    """在后台线程里跑一个网页服务, 退出时自动关闭。"""

    def __init__(self):
        self.httpd = webapp.SDesWebServer(("127.0.0.1", 0), webapp.SDesWebHandler)
        self.port = self.httpd.server_address[1]
        # poll_interval 调小, 让 shutdown() 更快返回, 缩短测试总耗时
        self.thread = threading.Thread(
            target=lambda: self.httpd.serve_forever(poll_interval=0.05), daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        return False

    # -- 请求辅助 ---------------------------------------------------------
    def get_raw(self, path: str):
        """返回 (status, body_bytes); HTTPError 也当作正常返回处理。"""
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method="GET")
        return self._open(req)

    def get(self, path: str):
        status, raw = self.get_raw(path)
        return status, json.loads(raw.decode("utf-8"))

    def post(self, path: str, payload: dict):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        status, raw = self._open(req)
        return status, json.loads(raw.decode("utf-8"))

    @staticmethod
    def _open(req):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


def test_static() -> None:
    print("\n--- 1. 静态资源 ---")
    with _LiveWeb() as web:
        status, html = web.get_raw("/")
        check("GET / 返回 200", status == 200, f"HTTP {status}")
        text = html.decode("utf-8")
        check("首页包含标题", "S-DES" in text and "第 1 关" in text)
        check("首页包含 5 个关卡页签",
              all(f"第 {i} 关" in text for i in range(1, 6)))

        for path, needle in (("/style.css", ":root"), ("/app.js", "api(")):
            status, raw = web.get_raw(path)
            check(f"GET {path} 返回 200", status == 200, f"HTTP {status}")
            check(f"{path} 内容非空", needle in raw.decode("utf-8"))

        status, _ = web.get_raw("/no-such-file.js")
        check("未知静态资源返回 404", status == 404, f"HTTP {status}")

        status, _ = web.get_raw("/../sdes/core.py")
        check("目录穿越被拒绝 (403/404)", status in (403, 404), f"HTTP {status}")


def test_meta_and_spec_tables() -> None:
    print("\n--- 2. 规格接口 /api/meta ---")
    with _LiveWeb() as web:
        status, body = web.get("/api/meta")
        check("/api/meta 返回 200 且 ok=True", status == 200 and body.get("ok") is True)
        data = body["data"]
        check("版本号与包一致", data["version"] == webapp.__version__, data["version"])
        check("分组/密钥位数正确",
              data["block_bits"] == 8 and data["key_bits"] == 10)

        tables = data["tables"]
        expect = {
            "P10": core.P10, "P8": core.P8, "IP": core.IP, "IP_INV": core.IP_INV,
            "EP": core.EP, "SPBOX": core.SPBOX,
        }
        for name, table in expect.items():
            check(f"{name} 与 core 一致",
                  tuple(tables[name]) == tuple(table),
                  str(tables[name]))
        check("SBox1 与 core 一致",
              [tuple(r) for r in tables["SBOX1"]] == [tuple(r) for r in core.SBOX1])
        check("SBox2 与 core 一致",
              [tuple(r) for r in tables["SBOX2"]] == [tuple(r) for r in core.SBOX2])
        check("明确提示 SBox2 与标准不同", "SBox2" in data["note"])


def test_single_block_matches_core() -> None:
    print("\n--- 3. 单分组加解密与 core 一致 ---")
    with _LiveWeb() as web:
        cases = [
            ("10010111", "1010000010"),
            ("00000000", "0000011111"),
            ("11111111", "1111111111"),
            ("10101010", "0101010101"),
        ]
        for pt, key in cases:
            status, body = web.post("/api/encrypt", {"plaintext": pt, "key": key})
            ok = status == 200 and body.get("ok") is True
            if not check(f"加密 {pt}/{key} 返回成功", ok):
                continue
            data = body["data"]
            expect_ct = core.encrypt(pt, key)
            expect_k1, expect_k2 = core.key_schedule(key)
            check(f"密文与 core.encrypt 一致 ({pt} -> {expect_ct})",
                  data["ciphertext"] == expect_ct, data["ciphertext"])
            check("K1/K2 与 key_schedule 一致",
                  data["k1"] == core.int_to_bits(expect_k1, 8)
                  and data["k2"] == core.int_to_bits(expect_k2, 8))
            check("密文 hex 与二进制自洽",
                  int(data["ciphertext_hex"], 16) == int(expect_ct, 2),
                  data["ciphertext_hex"])
            check("返回逐步中间状态",
                  "P10(K)" in data["steps"] and "IP^-1(...) = C" in data["steps"])
            check("跟踪表最后一步等于密文",
                  data["steps"]["IP^-1(...) = C"] == expect_ct)

            status, body = web.post("/api/decrypt", {"ciphertext": expect_ct, "key": key})
            check(f"解密 {expect_ct} 还原 {pt}",
                  status == 200 and body["data"]["plaintext"] == pt)

        # 位串允许带空格/下划线
        status, body = web.post("/api/encrypt", {"plaintext": "1001 0111", "key": "1010_0000_10"})
        check("接受带分隔符的位串输入",
              status == 200 and body["data"]["ciphertext"] == core.encrypt("10010111", "1010000010"))


def test_text_and_codec() -> None:
    print("\n--- 4. 字符串加解密与 codec 一致 ---")
    with _LiveWeb() as web:
        key = "1010000010"
        samples = ["This is a test", "信息安全导论", "A", "Hello, S-DES! 1234567890",
                   "多行\n文本\r测试", "反斜杠\\与\\n字面量"]
        for text in samples:
            status, body = web.post("/api/text/encrypt", {"text": text, "key": key})
            if not check(f"加密 {text!r} 成功", status == 200 and body.get("ok") is True):
                continue
            data = body["data"]
            expect = codec.encrypt_text_hex(text, key)
            check(f"密文与 codec 一致 ({len(text)} 字符)",
                  data["ciphertext_hex"] == expect, data["ciphertext_hex"][:32])
            check("字节数与 UTF-8 编码长度一致",
                  data["byte_count"] == len(text.encode("utf-8")), str(data["byte_count"]))

            status, body = web.post("/api/text/decrypt",
                                    {"hex": expect, "key": key})
            check(f"解密回原字符串 {text!r}",
                  status == 200 and body["data"]["text"] == text)

        status, body = web.post("/api/text/encrypt",
                                {"text": "中文", "key": key, "encoding": "gbk"})
        check("支持 GBK 编码",
              status == 200 and body["data"]["ciphertext_hex"] == codec.encrypt_text_hex("中文", key, "gbk"))

        status, body = web.post("/api/text/decrypt", {"hex": "ABC", "key": key})
        check("奇数长度 hex 返回 400", status == 400 and "十六进制" in body["error"],
              body.get("error", ""))
        status, body = web.post("/api/text/decrypt", {"hex": "ZZZZ", "key": key})
        check("非法 hex 字符返回 400", status == 400, body.get("error", ""))


def test_vectors_and_compare() -> None:
    print("\n--- 5. 测试向量生成 / 比对 (第 2 关) ---")
    with _LiveWeb() as web:
        status, body = web.post("/api/vectors", {"count": 12})
        check("生成 12 条向量", status == 200 and body["data"]["count"] == 12)
        data = body["data"]
        check("种子固定为 20261008", data["seed"] == webapp.VECTOR_SEED)
        check("CSV 表头为 pt,key,ct", data["csv"].splitlines()[0] == "pt,key,ct")
        check("CSV 行数 = 条数 + 表头",
              len(data["csv"].strip().splitlines()) == 13,
              str(len(data["csv"].strip().splitlines())))

        rows = data["rows"]
        check("每条向量都能被 core 复现",
              all(core.encrypt(r["pt"], r["key"]) == r["ct"] for r in rows))
        check("位宽正确",
              all(len(r["pt"]) == 8 and len(r["key"]) == 10 and len(r["ct"]) == 8 for r in rows))

        # 同种子两次生成必须完全一致(可复现)
        _, body2 = web.post("/api/vectors", {"count": 12})
        check("相同种子结果可复现", body2["data"]["csv"] == data["csv"])

        csv_a = data["csv"]
        status, body = web.post("/api/vectors/compare", {"csv_a": csv_a, "csv_b": csv_a})
        check("自己与自己比对 -> 一致",
              status == 200 and body["data"]["same"] is True, str(body["data"]["total"]))

        tampered = csv_a.replace(rows[0]["ct"], "00000000", 1)
        status, body = web.post("/api/vectors/compare", {"csv_a": csv_a, "csv_b": tampered})
        check("篡改一行 -> 判定不一致",
              status == 200 and body["data"]["same"] is False)
        check("差异条目被列出", len(body["data"]["mismatches"]) >= 1)

        # 测试向量是随机抽样, 允许出现完全重复的行; 重复行不能算差异
        dup = csv_a.strip() + "\n" + data["csv"].strip().splitlines()[-1] + "\n"
        status, body = web.post("/api/vectors/compare", {"csv_a": csv_a, "csv_b": dup})
        check("对方多一条重复行 -> 仅计 1 处差异(行数不同)",
              status == 200 and body["data"]["same"] is False
              and body["data"]["mismatch_count"] == 1,
              str(body["data"].get("mismatch_count")))
        status, body = web.post("/api/vectors/compare", {"csv_a": csv_a, "csv_b": csv_a})
        check("相同内容零差异(重复行不算差异)",
              status == 200 and body["data"]["mismatch_count"] == 0,
              str(body["data"].get("mismatch_count")))

        status, body = web.post("/api/vectors/compare", {"csv_a": csv_a, "csv_b": "pt,key,ct"})
        check("对方 CSV 无数据行 -> 400", status == 400, body.get("error", ""))
        status, body = web.post("/api/vectors", {"count": 0})
        check("条数 0 -> 400", status == 400, body.get("error", ""))
        status, body = web.post("/api/vectors", {"count": 999999})
        check("条数超上限 -> 400", status == 400, body.get("error", ""))


def test_crack_matches_crack_module() -> None:
    print("\n--- 6. 暴力破解接口 (第 4 关) ---")
    with _LiveWeb() as web:
        pt, key = "10010111", "1010000010"
        ct = core.encrypt(pt, key)

        status, body = web.post("/api/crack", {"pairs": [[pt, ct]], "threaded": True, "workers": 8})
        check("单对破解返回成功", status == 200 and body.get("ok") is True)
        data = body["data"]
        expect = crack.brute_force([(pt, ct)])["keys"]
        expect_bits = sorted(core.int_to_bits(k, core.KEY_BITS) for k in expect)
        check("多线程候选集与单线程一致", sorted(data["keys"]) == expect_bits,
              f"{data['keys']}")
        check("候选含真实密钥", key in data["keys"])
        check("遍历全部 1024 个密钥", data["tried"] == 1024, str(data["tried"]))
        check("候选数在合理范围 2~12", 2 <= data["key_count"] <= 12, str(data["key_count"]))
        check("返回耗时(ms)为正", data["elapsed_ms"] > 0)

        status, body = web.post("/api/crack", {"pairs": [[pt, ct]], "threaded": False})
        single = body["data"]
        check("单线程与多线程候选集一致", sorted(single["keys"]) == sorted(data["keys"]))

        # 两对 -> 候选数下降
        second_pt = "00000000"
        status, body = web.post("/api/crack",
                                {"pairs": [[pt, ct], [second_pt, core.encrypt(second_pt, key)]]})
        check("两对明密文使候选数下降",
              body["data"]["key_count"] <= data["key_count"],
              f"单对 {data['key_count']} -> 两对 {body['data']['key_count']}")
        check("两对结果仍含真实密钥", key in body["data"]["keys"])

        status, body = web.post("/api/crack", {"pairs": []})
        check("空明密文对 -> 400", status == 400, body.get("error", ""))
        status, body = web.post("/api/crack", {"pairs": [["111", "00000000"]]})
        check("位宽错误 -> 400", status == 400, body.get("error", ""))


def test_collisions_and_report() -> None:
    print("\n--- 7. 封闭测试接口 (第 5 关) ---")
    with _LiveWeb() as web:
        status, body = web.post("/api/collisions", {"sample": 0})
        check("全空间分析返回成功", status == 200 and body.get("ok") is True)
        data = body["data"]
        check("密钥空间 1024", data["key_space"] == 1024, str(data["key_space"]))
        check("明文空间 256", data["block_space"] == 256, str(data["block_space"]))
        check("枚举组合数 262144", data["total_pairs"] == 1024 * 256, str(data["total_pairs"]))
        check("最大碰撞桶 >= 2 (鸽巢原理)",
              data["max_bucket"] >= 2, f"{data['max_bucket']} 个密钥")
        check("不存在全局等价密钥类",
              data["equivalent_classes"] == 0, str(data["equivalent_classes"]))
        check("平均候选密钥约为 1024/256 = 4",
              3.5 <= data["avg_candidates_per_cipher"] <= 5.0,
              f"{data['avg_candidates_per_cipher']:.3f}")
        check("桶大小分布非空", len(data["buckets"]) > 0)
        # buckets 是 "桶大小 -> 该大小的桶个数" 的直方图;
        # 每个 (明文, 密文) 桶里装着 size 个密钥, 所以 sum(size * count) 应等于全部组合数。
        check("桶内密钥数之和 = 枚举组合数",
              sum(b["size"] * b["count"] for b in data["buckets"]) == data["total_pairs"],
              str(sum(b["size"] * b["count"] for b in data["buckets"])))
        check("样例明文位串为 8 bit", len(data["sample"]["plaintext"]) == 8)
        check("样例碰撞条目非空", len(data["sample"]["cases"]) > 0)
        check("样例中每个密文确有多个密钥",
              all(len(c["keys"]) > 1 for c in data["sample"]["cases"]))

        status, body = web.post("/api/collisions", {"sample": 300})
        check("样例明文越界 -> 400", status == 400, body.get("error", ""))

        status, body = web.get("/api/report")
        check("碰撞报告返回 200", status == 200 and body.get("ok") is True)
        text = body["data"]["text"]
        check("报告含密钥空间/明文空间结论",
              "1024" in text and "256" in text)
        check("报告文本与 crack.collision_report 一致",
              text == crack.collision_report(0))


def test_error_handling() -> None:
    print("\n--- 8. 错误处理 ---")
    with _LiveWeb() as web:
        status, body = web.post("/api/nope", {})
        check("未知接口 -> 404", status == 404 and body.get("ok") is False, body.get("error", ""))

        # 直接发非法 JSON
        req = urllib.request.Request(
            f"http://127.0.0.1:{web.port}/api/encrypt",
            data=b"{not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        status, raw = _LiveWeb._open(req)
        check("非法 JSON -> 400", status == 400, str(status))
        check("错误信息可读", "JSON" in json.loads(raw.decode("utf-8"))["error"])

        for payload, needle in (
            ({"plaintext": "", "key": "1010000010"}, "明文"),
            ({"plaintext": "10010111", "key": "101"}, "密钥"),
            ({"plaintext": "1001011x", "key": "1010000010"}, "0 和 1"),
        ):
            status, body = web.post("/api/encrypt", payload)
            check(f"非法输入返回 400 且提示“{needle}”",
                  status == 400 and needle in body.get("error", ""),
                  body.get("error", ""))

        # 服务端未启动时的友好错误(端口 1 基本不可能有服务)
        status, body = web.post("/api/tcp/send",
                                {"host": "127.0.0.1", "port": 1, "key": "1010000010", "text": "hi"})
        check("TCP 服务端未启动 -> 502 且给出中文提示",
              status == 502 and "sdes.server" in body.get("error", ""),
              body.get("error", ""))

        status, body = web.post("/api/tcp/send",
                                {"host": "127.0.0.1", "port": 1, "key": "1010000010", "text": ""})
        check("发送空内容 -> 400", status == 400, body.get("error", ""))


def test_tcp_end_to_end() -> None:
    print("\n--- 9. 网页接口 -> TCP 服务端 端到端 ---")
    from sdes.server import SDesServer

    key = "1010000010"
    server = SDesServer(("127.0.0.1", 0), key)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with _LiveWeb() as web:
            for text in ("This is a test", "信息安全导论"):
                status, body = web.post("/api/tcp/send", {
                    "host": "127.0.0.1", "port": port, "key": key, "text": text,
                })
                if not check(f"发送 {text!r} 成功", status == 200 and body.get("ok") is True):
                    continue
                data = body["data"]
                check("服务端回显与原文一致", data["ok"] is True)
                check("密文与本地 codec 一致",
                      data["ciphertext_hex"] == codec.encrypt_text_hex(text, key))
                check("服务端密钥可回读", data["server_key"] == key)
                check("返回分步日志", len(data["log"]) >= 5)

            # 密钥不一致时 service 仍应答, 但回显应为乱码 / 校验失败
            status, body = web.post("/api/tcp/send", {
                "host": "127.0.0.1", "port": port, "key": "0000011111", "text": "abc",
            })
            check("密钥不同时给出校验失败(而非崩溃)",
                  status == 200 and body["data"]["ok"] is False,
                  f"回显 {body['data']['server_plaintext']!r}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_independent_vectors() -> None:
    """第 2 关单人交叉测试: tests/gen_vectors.py 独立第二实现。

    这一步不经过 HTTP, 而是直接验证「对方的程序」——
    ``tests/gen_vectors.py`` 刻意不 import ``sdes``, 置换表与流程按作业
    文档重抄一遍, 因此它与 ``sdes.core`` 的一致性就是真正的交叉测试。
    """
    print("\n--- 10. 独立第二实现交叉测试 (tests/gen_vectors.py) ---")
    from tests import gen_vectors

    check("独立实现与 core 的规格表一致",
          (gen_vectors.P10, gen_vectors.P8, gen_vectors.IP, gen_vectors.IP_INV,
           gen_vectors.EP, gen_vectors.SPBOX, gen_vectors.SBOX1, gen_vectors.SBOX2)
          == (core.P10, core.P8, core.IP, core.IP_INV,
              core.EP, core.SPBOX, core.SBOX1, core.SBOX2))

    rows = gen_vectors.build_rows(200)
    check("生成 200 条向量", len(rows) == 200, str(len(rows)))

    mismatch = [(pt, k, ct, core.encrypt(pt, k)) for pt, k, ct in rows
                if core.encrypt(pt, k) != ct]
    check("200 条密文与 core 逐条一致(独立实现交叉验证)",
          mismatch == [], f"{len(mismatch)} 条不一致, 首条 {mismatch[:1]}")

    check("位宽正确",
          all(len(pt) == 8 and len(k) == 10 and len(ct) == 8 for pt, k, ct in rows))

    csv = gen_vectors.to_csv(rows)
    check("CSV 表头为 pt,key,ct", csv.splitlines()[0] == "pt,key,ct")
    check("CSV 行数 = 条数 + 1", len(csv.strip().splitlines()) == 201)

    # 与网页版同一取样序列: 明文/密钥两列必须与 /api/vectors 完全一致
    with _LiveWeb() as web:
        _, body = web.post("/api/vectors", {"count": 200})
    web_rows = [(r["pt"], r["key"]) for r in body["data"]["rows"]]
    check("取样序列与网页版一致(pt/key 列相同)",
          web_rows == [(pt, k) for pt, k, _ in rows])

    # 固定密钥模式
    fixed = gen_vectors.build_rows(20, "1010000010")
    check("固定密钥模式生效", all(k == "1010000010" for _, k, _ in fixed))
    check("固定密钥模式下密文仍与 core 一致",
          all(core.encrypt(pt, k) == ct for pt, k, ct in fixed))

    # core.key_schedule 返回 int, gen_vectors 返回 0/1 串, 比较时统一成位串
    check("密钥扩展与 core 一致",
          all(tuple(format(x, "08b") for x in core.key_schedule(int(k, 2)))
              == gen_vectors.key_schedule(k)
              for _, k, _ in rows[:50]))


def main() -> int:
    print("=" * 68)
    print("S-DES 网页版界面 自测套件 (第 6 关 · 附加)")
    print("=" * 68)
    test_static()
    test_meta_and_spec_tables()
    test_single_block_matches_core()
    test_text_and_codec()
    test_vectors_and_compare()
    test_crack_matches_crack_module()
    test_collisions_and_report()
    test_error_handling()
    test_tcp_end_to_end()
    test_independent_vectors()
    print("=" * 68)
    if _FAILURES:
        print(f"结果: {len(_FAILURES)} 项失败")
        for name in _FAILURES:
            print(f"  - {name}")
        return 1
    print("结果: 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
