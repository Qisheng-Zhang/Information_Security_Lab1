"""S-DES 自测套件。

覆盖:
  1. 规格表一致性(与作业文档逐项比对)
  2. 密钥调度
  3. 加解密回环(穷举全部 256 明文 x 抽查密钥)
  4. 双实现交叉验证(整数位运算 vs 字符串置换)
  5. 雪崩效应
  6. 第 3 关 ASCII 编解码
  7. 第 4 关暴力破解(单线程 vs 多线程一致性)
  8. 第 5 关碰撞统计

运行:  python -m tests.test_all      (在项目根目录)
"""

from __future__ import annotations

import itertools
import random

from sdes import core
from sdes.codec import (
    bits_to_bytes, bits_to_hex, bits_to_text, bytes_to_bits,
    decrypt_bytes, decrypt_text, encrypt_bytes, encrypt_text, hex_to_bits,
    split_blocks, text_to_bits,
)
from sdes.crack import (
    analyze_collisions, brute_force, brute_force_threaded, equivalent_key_classes,
)

_FAILURES: list = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    line = f"[{status}] {name}"
    if detail:
        line += f"  --  {detail}"
    print(line)
    if not condition:
        _FAILURES.append(name)


# ---------------------------------------------------------------------------
# 1. 规格表
# ---------------------------------------------------------------------------

def test_spec_tables() -> None:
    print("\n--- 1. 规格表一致性 ---")
    check("P10 = (3,5,2,7,4,10,1,9,8,6)", core.P10 == (3, 5, 2, 7, 4, 10, 1, 9, 8, 6))
    check("P8  = (6,3,7,4,8,5,10,9)", core.P8 == (6, 3, 7, 4, 8, 5, 10, 9))
    check("IP  = (2,6,3,1,4,8,5,7)", core.IP == (2, 6, 3, 1, 4, 8, 5, 7))
    check("IP^-1 = (4,1,3,5,7,2,8,6)", core.IP_INV == (4, 1, 3, 5, 7, 2, 8, 6))
    check("EPBox = (4,1,2,3,2,3,4,1)", core.EP == (4, 1, 2, 3, 2, 3, 4, 1))
    check("SPBox = (2,4,3,1)", core.SPBOX == (2, 4, 3, 1))
    check("Shift1 = (2,3,4,5,1) 等价左移 1 位", _shift_table(1) == (2, 3, 4, 5, 1))
    check("Shift2 = (3,4,5,1,2) 等价左移 2 位", _shift_table(2) == (3, 4, 5, 1, 2))

    # S 盒按表格文字逐格核对
    sbox1_rows = [(1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2)]
    sbox2_rows = [(0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3)]
    check("SBox1 数值 = [(1,0,3,2);(3,2,1,0);(0,2,1,3);(3,1,0,2)]",
          tuple(core.SBOX1) == tuple(sbox1_rows))
    check("SBox2 数值 = [(0,1,2,3);(2,3,1,0);(3,0,1,2);(2,1,0,3)]",
          tuple(core.SBOX2) == tuple(sbox2_rows))

    # 与文档中渲染的 S 盒表格(行=首末位, 列=中间两位)核对
    check("SBox1 表格逐格一致",
          _sbox_grid(core.SBOX1) ==
          [[(0, 1), (0, 0), (1, 1), (1, 0)],
           [(1, 1), (1, 0), (0, 1), (0, 0)],
           [(0, 0), (1, 0), (0, 1), (1, 1)],
           [(1, 1), (0, 1), (0, 0), (1, 0)]])
    check("SBox2 表格逐格一致",
          _sbox_grid(core.SBOX2) ==
          [[(0, 0), (0, 1), (1, 0), (1, 1)],
           [(1, 0), (1, 1), (0, 1), (0, 0)],
           [(1, 1), (0, 0), (0, 1), (1, 0)],
           [(1, 0), (0, 1), (0, 0), (1, 1)]])

    # 与标准 S-DES 对比: SBox1 相同, SBox2 不同
    std_s0 = ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2))
    std_s1 = ((0, 1, 2, 3), (2, 0, 1, 3), (3, 0, 1, 0), (2, 1, 0, 3))
    check("SBox1 与标准 S-DES 的 S0 相同", tuple(core.SBOX1) == std_s0)
    check("SBox2 与标准 S-DES 的 S1 不同(作业已改)", tuple(core.SBOX2) != std_s1)


def _shift_table(k: int) -> tuple:
    """左移 k 位对应的 5 位置换表(1-indexed)。"""
    return tuple((i + k) % 5 + 1 for i in range(5))


def _sbox_grid(box) -> list:
    """把 S 盒还原成文档中的表格形式(二进制元组), 用于逐格核对。"""
    grid = []
    for row in box:
        grid.append([tuple(int(b) for b in format(v, "02b")) for v in row])
    return grid


# ---------------------------------------------------------------------------
# 2. 密钥调度
# ---------------------------------------------------------------------------

def test_key_schedule() -> None:
    print("\n--- 2. 密钥扩展 ---")
    k = 0b1010000010
    k1, k2 = core.key_schedule(k)
    # 手工核对: P10 输出 = 1000001100 -> 左 5 位 10000, 右 5 位 01100
    permuted = core._permute(k, 10, core.P10)
    check("P10(1010000010) = 1000001100", format(permuted, "010b") == "1000001100",
          format(permuted, "010b"))
    left1 = core._rot_left(0b10000, 5, 1)
    right1 = core._rot_left(0b01100, 5, 1)
    check("K1 计算与公式一致",
          k1 == core._permute((left1 << 5) | right1, 10, core.P8))
    left2 = core._rot_left(left1, 5, 2)
    right2 = core._rot_left(right1, 5, 2)
    check("K2 计算与公式一致",
          k2 == core._permute((left2 << 5) | right2, 10, core.P8))
    check("K1, K2 均为 8 bit", k1 < 256 and k2 < 256)
    check("K1 != K2 (一般情况)", k1 != k2, f"K1={k1:08b} K2={k2:08b}")
    # 全零 / 全一密钥不应崩溃
    for kk in (0, 0b1111111111):
        a, b = core.key_schedule(kk)
        check(f"密钥 {kk:010b} 可调度且 K1,K2 < 256", a < 256 and b < 256)


# ---------------------------------------------------------------------------
# 3. 回环
# ---------------------------------------------------------------------------

def test_roundtrip() -> None:
    print("\n--- 3. 加解密回环 ---")
    bad = 0
    keys = [0, 1, 0b1111111111, 0b1010000010, 0b0000011111, 0b1100110011]
    for k in keys:
        for p in range(256):
            c = core.encrypt_int(p, k)
            if core.decrypt_int(c, k) != p:
                bad += 1
    total = 256 * len(keys)
    check(f"全部 {total} 组 (密钥,明文) 加解密回环一致", bad == 0, f"失败 {bad} 组")

    # 随机抽查
    random.seed(20261008)
    bad = sum(1 for _ in range(20000)
              if core.decrypt_int(core.encrypt_int(p := random.randrange(256),
                                                   k := random.randrange(1024)), k) != p)
    check("随机 20000 组回环一致", bad == 0, f"失败 {bad} 组")

    # 置换可逆性: IP 与 IP^-1
    check("IP 与 IP^-1 互逆", all(
        core._permute(core._permute(x, 8, core.IP), 8, core.IP_INV) == x
        for x in range(256)))


# ---------------------------------------------------------------------------
# 4. 双实现交叉验证
# ---------------------------------------------------------------------------

def test_cross_implementation() -> None:
    print("\n--- 4. 双实现交叉验证(整数位运算 vs 字符串逐位置换) ---")
    mismatch = 0
    for k in (0, 0b1010000010, 0b1111111111, 0b0101010101):
        kbits = format(k, "010b")
        for p in range(256):
            expected = _ref_encrypt(format(p, "08b"), kbits)
            if core.encrypt(format(p, "08b"), kbits) != expected:
                mismatch += 1
    check("1024 组加密结果与参考实现完全一致", mismatch == 0, f"不一致 {mismatch} 组")


def _ref_encrypt(plaintext: str, key: str) -> str:
    """参考实现: 完全按作业文档的字符串置换写法, 独立于 core 的位运算。"""
    def perm(bits: str, table) -> str:
        return "".join(bits[i - 1] for i in table)

    def left_shift(bits: str, n: int) -> str:
        n %= len(bits)
        return bits[n:] + bits[:n]

    def sbox(bits: str, box) -> str:
        row = int(bits[0] + bits[3], 2)
        col = int(bits[1] + bits[2], 2)
        return format(box[row][col], "02b")

    def f(right: str, subkey: str) -> str:
        x = _xor(perm(right, core.EP), subkey)
        return perm(sbox(x[:4], core.SBOX1) + sbox(x[4:], core.SBOX2), core.SPBOX)

    def fk(bits: str, subkey: str) -> str:
        left, right = bits[:4], bits[4:]
        return _xor(left, f(right, subkey)) + right

    p10 = perm(key, core.P10)
    left, right = p10[:5], p10[5:]
    k1 = perm(left_shift(left, 1) + left_shift(right, 1), core.P8)
    left, right = left_shift(left, 1), left_shift(right, 1)
    k2 = perm(left_shift(left, 2) + left_shift(right, 2), core.P8)

    state = fk(perm(plaintext, core.IP), k1)
    state = state[4:] + state[:4]
    state = fk(state, k2)
    return perm(state, core.IP_INV)


def _xor(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# 5. 雪崩效应
# ---------------------------------------------------------------------------

def test_avalanche() -> None:
    print("\n--- 5. 雪崩效应 ---")
    key = 0b1010000010
    total_flips = 0
    trials = 0
    for p in range(256):
        base = core.encrypt_int(p, key)
        for bit in range(8):
            flipped = core.encrypt_int(p ^ (1 << bit), key)
            total_flips += bin(base ^ flipped).count("1")
            trials += 1
    avg = total_flips / trials
    check(f"单比特明文翻转引起密文平均 {avg:.3f} bit 变化(理想 4.0)", 3.0 <= avg <= 5.0)

    total_flips = 0
    trials = 0
    for k in range(1024):
        k1, k2 = core.key_schedule(k)
        for bit in range(10):
            a1, a2 = core.key_schedule(k ^ (1 << bit))
            total_flips += bin(k1 ^ a1).count("1") + bin(k2 ^ a2).count("1")
            trials += 2
    avg_k = total_flips / trials
    # S-DES 密钥调度扩散性很弱: P8 丢弃部分位置, 单比特翻转平均只影响
    # 约 0.8 bit/子密钥 (1.6 bit/两个子密钥), 这是算法固有性质而非实现缺陷。
    check(f"单比特密钥翻转引起子密钥平均 {avg_k:.3f} bit 变化(弱扩散, <=2.0)",
          avg_k <= 2.0)

    # 用密文层面衡量密钥雪崩: 固定明文, 翻转密钥 1 bit 观察密文变化
    total_flips = 0
    trials = 0
    pt = 0b10010111
    for k in range(1024):
        base = core.encrypt_int(pt, k)
        for bit in range(10):
            flipped = core.encrypt_int(pt, k ^ (1 << bit))
            total_flips += bin(base ^ flipped).count("1")
            trials += 1
    avg_ct = total_flips / trials
    check(f"单比特密钥翻转引起密文平均 {avg_ct:.3f} bit 变化(理想 4.0)",
          2.5 <= avg_ct <= 3.5)


# ---------------------------------------------------------------------------
# 6. 第 3 关 ASCII 编解码
# ---------------------------------------------------------------------------

def test_codec() -> None:
    print("\n--- 6. 第 3 关 ASCII 字符串加解密 ---")
    key = "1010000010"
    samples = ["This is a test", "信息安全导论", "A", "", "Hello, S-DES! 1234567890"]
    for s in samples:
        if s == "":
            check("空字符串往返", encrypt_bytes(b"", key) == b"" and decrypt_bytes(b"", key) == b"")
            continue
        ct = encrypt_bytes(s.encode("utf-8"), key)
        pt = decrypt_bytes(ct, key).decode("utf-8")
        check(f"字节往返: {s[:20]!r}", pt == s)
        check(f"bit 串往返: {s[:20]!r}", decrypt_text(encrypt_text(s, key), key) == s)

    # 明文 "This is a test" 首字节 'T' = 0x54 = 01010100
    check("text_to_bits('T') = 01010100", text_to_bits("T") == "01010100")
    check("bytes_to_bits 反解一致", bits_to_bytes(bytes_to_bits(b"\x00\xff")) == b"\x00\xff")
    check("hex_to_bits('A5') = 10100101", hex_to_bits("A5") == "10100101")
    check("bits_to_hex('10100101') = A5", bits_to_hex("10100101") == "A5")
    check("分组切开再合并无损",
          "".join(split_blocks(text_to_bits("abc"), 8)) == text_to_bits("abc"))
    check("非法长度 bit 串报错", _raises(lambda: bits_to_bytes("101")))

    # 单字节分组: 密文长度必须与明文一致(1 Byte 一组)
    msg = "This is a test"
    check("密文长度 = 明文字节数",
          len(encrypt_bytes(msg.encode(), key)) == len(msg.encode()))


def _raises(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


# ---------------------------------------------------------------------------
# 7. 第 4 关暴力破解
# ---------------------------------------------------------------------------

def test_brute_force() -> None:
    print("\n--- 7. 第 4 关暴力破解 ---")
    truth = 0b1010000010
    p = 0b10010111
    c = core.encrypt_int(p, truth)

    single = brute_force([(p, c)])
    check("单线程破解结果包含真实密钥", truth in single["keys"], f"{len(single['keys'])} 个候选")
    check("单线程遍历 1024 个密钥", single["tried"] == 1024)
    check("单对候选数在合理范围(2~12)", 2 <= len(single["keys"]) <= 12,
          f"实际 {len(single['keys'])}")

    multi = brute_force_threaded([(p, c)], workers=8, chunk=32)
    check("多线程与单线程候选集合一致", sorted(multi["keys"]) == sorted(single["keys"]))
    check("多线程同样遍历 1024 个密钥", multi["tried"] == 1024)
    print(f"      单线程 {single['elapsed'] * 1000:.3f} ms, "
          f"多线程(8 线程) {multi['elapsed'] * 1000:.3f} ms")

    # 两个明文-密文对 -> 大幅收窄
    p2 = 0b00000001
    c2 = core.encrypt_int(p2, truth)
    two = brute_force([(p, c), (p2, c2)])
    check("两对后候选数骤降(通常唯一)", len(two["keys"]) <= len(single["keys"]),
          f"两对 {len(two['keys'])} 个, 单对 {len(single['keys'])} 个")
    check("两对结果包含真实密钥", truth in two["keys"])

    # 多线程在不同线程数下结果稳定
    for w in (1, 2, 4, 16):
        r = brute_force_threaded([(p, c)], workers=w, chunk=17)
        if sorted(r["keys"]) != sorted(single["keys"]):
            check(f"workers={w} 结果一致", False)
            break
    else:
        check("workers=1/2/4/16 结果全部一致", True)

    # 大数据集: 全部 256 个明文对 -> 应唯一确定
    pairs = [(x, core.encrypt_int(x, truth)) for x in range(256)]
    full = brute_force(pairs, want_all=True)
    check("256 对明文密文唯一确定密钥", full["keys"] == [truth],
          f"得到 {[format(k, '010b') for k in full['keys']]}")


# ---------------------------------------------------------------------------
# 8. 第 5 关碰撞
# ---------------------------------------------------------------------------

def test_collisions() -> None:
    print("\n--- 8. 第 5 关密钥碰撞 ---")
    # 全局等价: (K1,K2) 完全相同的密钥组。
    # 注意结论是"不存在" —— P8 对 K1 用左半的第 3/4/5 位并丢弃第 1/2 位,
    # 但 K2 是在左移 2 位后取同一组位置, 于是第 1/2 位又在 K2 中被用到;
    # 右半 5 位则在 K1/K2 中始终被使用。因此没有任何密钥比特是全程冗余的,
    # 不存在行为完全相同的两个主密钥。
    classes = equivalent_key_classes()
    total_in_classes = sum(len(g) for g in classes)
    check("不存在行为完全相同的密钥组(无全程冗余密钥比特)",
          len(classes) == 0, f"{len(classes)} 组, 覆盖 {total_in_classes} 个密钥")

    # 每对子密钥互不相同 => 单主密钥映射到唯一 (K1,K2)
    pairs = {core.key_schedule(k) for k in range(1024)}
    check("1024 个主密钥映射到 1024 个不同的 (K1,K2)", len(pairs) == 1024,
          f"{len(pairs)} 个不同子密钥对")

    # 逐点验证(如果有等价类, 同一类内对所有明文输出必须相同)
    ok = True
    for grp in classes[:5]:
        for p in range(256):
            if len({core.encrypt_int(p, k) for k in grp}) != 1:
                ok = False
                break
    check("等价类内所有密钥对全部明文输出相同", ok)

    # 鸽巢: 密钥空间 1024 > 密文空间 256, 每个明文必然存在多密钥同密文
    stats = analyze_collisions()
    check("每个明文都存在多密钥 -> 同密文(鸽巢原理)",
          stats["max_bucket"] >= 2 and all(v["max"] >= 2 for v in stats["per_plaintext"].values()),
          f"最大桶 {stats['max_bucket']} 个密钥")
    check("碰撞不可避免: 密文空间 256 < 密钥空间 1024",
          stats["total_pairs"] == 256 * 1024, f"枚举 {stats['total_pairs']} 对")
    avg_cands = sum(v["avg_keys_per_cipher"] for v in stats["per_plaintext"].values()) / 256
    check(f"平均每个密文候选密钥 {avg_cands:.3f} 个(≈1024/256=4)",
          3.5 <= avg_cands <= 5.0)


# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 68)
    print("S-DES 自测套件")
    print("=" * 68)
    test_spec_tables()
    test_key_schedule()
    test_roundtrip()
    test_cross_implementation()
    test_avalanche()
    test_codec()
    test_brute_force()
    test_collisions()
    print("\n" + "=" * 68)
    if _FAILURES:
        print(f"结果: {len(_FAILURES)} 项失败")
        for name in _FAILURES:
            print(f"  - {name}")
        return 1
    print("结果: 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
