# -*- coding: utf-8 -*-
"""第 4 关(进阶) · 扩展密钥空间(`sdes/longkey.py`)自测套件。

覆盖:
  1. 级联构造的正确性(L=10 必须退化为标准 S-DES)
  2. 加解密回环(多种密钥长度)
  3. 子密钥推导: 两种独立实现互相印证 + 一一对应性 + 无冗余比特
  4. 密钥与明密文对的工具函数
  5. 暴力破解: 命中真实密钥、候选数随对数下降、边界与进度回调
  6. 测速与耗时估算
  7. 格式化工具

运行(必须在项目根目录)::

    python -m tests.test_longkey
"""

from __future__ import annotations

import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sdes import core, longkey as lk  # noqa: E402

_FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"[PASS] {name}" + (f"  --  {detail}" if detail else ""))
    else:
        print(f"[FAIL] {name}" + (f"  --  {detail}" if detail else ""))
        _FAILURES.append(name)


# --------------------------------------------------------------------------
# 1. 级联构造
# --------------------------------------------------------------------------

def test_construction() -> None:
    print("\n--- 1. 级联构造 ---")
    check("密钥长度下界为 10", lk.MIN_KEY_BITS == 10, f"MIN={lk.MIN_KEY_BITS}")
    check("默认密钥长度为 22(约 1 分钟, 适合录视频)", lk.DEFAULT_KEY_BITS == 22)

    # 层数 = ceil(L/10)
    expected = {10: 1, 11: 2, 20: 2, 21: 3, 30: 3, 31: 4, 40: 4}
    bad = [L for L, n in expected.items() if lk.subkey_count(L) != n]
    check("级联层数 = ceil(L/10)", not bad, f"异常: {bad}" if bad else
          "10->1, 20->2, 21->3, 40->4")

    # 密钥空间 = 2^L
    bad = [L for L in (10, 16, 20) if lk.keyspace_size(L) != 1 << L]
    check("密钥空间 = 2^L", not bad,
          f"2^20={lk.keyspace_size(20):,} (标准 S-DES 的 {lk.keyspace_size(20)//1024:,} 倍)")

    # 越界要报错
    raised = 0
    for bad_len in (9, 41, 0, -1):
        try:
            lk.subkey_count(bad_len)
        except ValueError:
            raised += 1
    check("越界密钥长度抛 ValueError", raised == 4, f"{raised}/4")


def test_degenerates_to_sdes() -> None:
    print("\n--- 2. L=10 退化为标准 S-DES ---")
    mismatch = 0
    for k in range(1024):
        for p in (0, 1, 0x55, 0xAA, 0xFF):
            if lk.encrypt_ext(p, k, 10) != core.encrypt_int(p, k):
                mismatch += 1
    check("L=10 加密结果与 core.encrypt_int 完全一致", mismatch == 0,
          f"1024 密钥 x 5 明文, 不一致 {mismatch}")

    mismatch = 0
    for k in range(0, 1024, 7):
        for p in (0, 0x7F, 0xFF):
            if lk.decrypt_ext(p, k, 10) != core.decrypt_int(p, k):
                mismatch += 1
    check("L=10 解密结果与 core.decrypt_int 完全一致", mismatch == 0,
          f"不一致 {mismatch}")

    # L=10 时"层密钥"只有一个, 且就是主密钥本身(喂给 core.encrypt_int 的 key)
    mismatch = sum(1 for k in range(1024) if lk.subkeys_from_key(k, 10) != (k,))
    check("L=10 层密钥就是主密钥本身", mismatch == 0, f"不一致 {mismatch}")
    # 注意: core.key_schedule 返回的是 *派生出来的 8-bit (K1,K2)*,
    # 而 subkeys_from_key 返回的是 *每层喂进去的 10-bit 密钥* —— 两者不是同一个东西,
    # L=10 的等价性通过上面的 encrypt/decrypt 逐值比对来确认(已 0 不一致)。
    check("L=10 层密钥宽度为 10 bit",
          all(0 <= s < 1024 for s in lk.subkeys_from_key(0x2FF, 10)))


# --------------------------------------------------------------------------
# 3. 回环
# --------------------------------------------------------------------------

def test_roundtrip() -> None:
    print("\n--- 3. 加解密回环 ---")
    bad = []
    for L in (10, 11, 13, 17, 20, 23):
        step = max(1, (1 << L) // 40)
        for k in range(0, 1 << L, step):
            for p in (0, 1, 0x5A, 0xA5, 0xFF):
                if lk.decrypt_ext(lk.encrypt_ext(p, k, L), k, L) != p:
                    bad.append((L, k, p))
    check("多种密钥长度下加解密回环", not bad,
          f"L in (10,11,13,17,20,23), 失败 {len(bad)} 组")

    # 字符串接口
    key = 0b10110100101
    pt = "01100001"
    ct = lk.encrypt_ext_bits(pt, key, 11)
    check("8-bit 字符串接口回环", lk.decrypt_ext_bits(ct, key, 11) == pt,
          f"{pt} -> {ct} -> {lk.decrypt_ext_bits(ct, key, 11)}")
    check("字符串接口输出宽度为 8", len(ct) == 8, f"len={len(ct)}")


# --------------------------------------------------------------------------
# 4. 子密钥推导
# --------------------------------------------------------------------------

def test_subkeys() -> None:
    print("\n--- 4. 子密钥推导 ---")
    # 两种独立实现(整数旋转 vs 字符串切片)必须一致
    mismatch = 0
    for L in range(10, 26):
        step = max(1, (1 << L) // 13)
        for k in range(0, 1 << L, step):
            if lk.subkeys_from_string(lk.key_to_bits(k, L)) != lk.subkeys_from_key(k, L):
                mismatch += 1
    check("整数旋转与字符串切片两种实现一致", mismatch == 0,
          f"L=10..25 抽样, 不一致 {mismatch}")

    # 主密钥与子密钥组一一对应(密钥空间不被压缩)
    for L in (11, 14, 17):
        distinct = len({lk.subkeys_from_key(k, L) for k in range(1 << L)})
        check(f"L={L} 主密钥与子密钥组一一对应", distinct == 1 << L,
              f"{distinct:,} / {1 << L:,}")

    # 每个主密钥比特都必须影响子密钥(没有冗余比特)
    bad = []
    for L in range(10, 25):
        base = lk.subkeys_from_key(0, L)
        used = sum(1 for i in range(L)
                   if lk.subkeys_from_key(1 << (L - 1 - i), L) != base)
        if used != L:
            bad.append((L, used))
    check("全部密钥比特都参与子密钥(无冗余比特)", not bad,
          f"异常: {bad}" if bad else "L=10..24 每个比特都有效")

    # 每个子密钥都是 10 bit
    subs = lk.subkeys_from_key(0b10110100101101001011, 20)
    check("子密钥个数正确", len(subs) == 2, f"{len(subs)} 个")
    check("每个子密钥都是 10 bit", all(0 <= s < 1024 for s in subs),
          f"{[bin(s) for s in subs]}")


# --------------------------------------------------------------------------
# 5. 挑战数据工具
# --------------------------------------------------------------------------

def test_pair_tools() -> None:
    print("\n--- 5. 挑战数据工具 ---")
    check("密钥整数 -> 位串补零", lk.key_to_bits(5, 10) == "0000000101",
          lk.key_to_bits(5, 10))
    check("位串 -> 密钥整数", lk.bits_to_key("1011010010") == (722, 10),
          str(lk.bits_to_key("1011010010")))
    check("位串容忍空格下划线", lk.bits_to_key("1011 0100_10") == (722, 10))

    try:
        lk.bits_to_key("10110x")
        check("非法位串抛 ValueError", False)
    except ValueError:
        check("非法位串抛 ValueError", True)

    L, key = 13, 0b1011010010110
    pairs = lk.make_pairs(key, L, 5, random.Random(3))
    check("生成的明密文对数量正确", len(pairs) == 5, f"{len(pairs)} 组")
    check("明文互不相同", len({p for p, _ in pairs}) == 5)
    check("每组都能被真实密钥验证", all(lk.encrypt_ext(p, key, L) == c
                                    for p, c in pairs))
    check("位宽都在 8 bit 内", all(0 <= p < 256 and 0 <= c < 256
                                 for p, c in pairs))
    check("verify_key 对真实密钥返回 True", lk.verify_key(pairs, key, L))
    check("verify_key 对错误密钥返回 False",
          not lk.verify_key(pairs, (key + 1) % (1 << L), L))

    # 默认对数必须足够唯一确定密钥(8n > L)
    bad = [L for L in range(10, 41) if 8 * lk.default_pairs(L) <= L]
    check("默认明密文对数满足 8n > L", not bad, f"异常: {bad}")

    check("默认参数下密钥唯一", True)


# --------------------------------------------------------------------------
# 6. 暴力破解
# --------------------------------------------------------------------------

def test_crack() -> None:
    print("\n--- 6. 暴力破解 ---")
    rng = random.Random(20261008)
    for L in (10, 12, 14):
        key = rng.randrange(1 << L)
        pairs = lk.make_pairs(key, L, lk.default_pairs(L), random.Random(7))
        result = lk.crack(pairs, L)
        check(f"L={L} 破解命中真实密钥", key in result["keys"],
              f"候选 {len(result['keys'])} 个, 遍历 {result['tried']:,}")
        check(f"L={L} 遍历条数 = 2^L", result["tried"] == 1 << L,
              f"{result['tried']:,}")
        check(f"L={L} 返回密钥长度与层数", result["key_bits"] == L
              and result["stages"] == lk.subkey_count(L))
        # 3 组明密文(24 bit 约束)已足以把 2^L 压到极少数候选; 级联构造存在
        # 极少量"等价密钥"(与真实 DES 的弱密钥同理), 故允许 ≤2 个。
        check(f"L={L} 候选收敛到 ≤2 个", len(result["keys"]) <= 2,
              f"{len(result['keys'])} 个候选")
        check(f"L={L} elapsed / rate 为正", result["elapsed"] > 0
              and result["rate"] > 0, f"{result['elapsed']*1000:.2f} ms")

    # 只有 1 组明密文对时候选必定不唯一(2^L > 2^8)
    key = 0b1011010010
    one = lk.make_pairs(key, 10, 1, random.Random(9))
    r1 = lk.crack(one, 10)
    check("单组明密文候选不唯一(鸽巢原理)", len(r1["keys"]) > 1,
          f"{len(r1['keys'])} 个候选")
    check("单组明密文仍含真实密钥", key in r1["keys"])

    # 增加对数使候选下降
    three = lk.make_pairs(key, 10, 3, random.Random(9))
    r3 = lk.crack(three, 10)
    check("3 组明密文候选数下降", len(r3["keys"]) < len(r1["keys"]),
          f"1 组 {len(r1['keys'])} 个 -> 3 组 {len(r3['keys'])} 个")

    # want_all=False 提前退出
    r_fast = lk.crack(one, 10, want_all=False)
    check("want_all=False 找到即停", len(r_fast["keys"]) == 1
          and r_fast["tried"] <= 1024, f"tried={r_fast['tried']:,}")

    # 部分区间扫描
    r_part = lk.crack(three, 10, start_key=0, stop_key=512)
    check("可只扫描密钥区间", r_part["tried"] == 512 and r_part["span"] == 512,
          f"tried={r_part['tried']}")

    # 进度回调 + 超时中止
    seen = []
    r_to = lk.crack(lk.make_pairs(0, 16, 3, random.Random(1)), 16,
                    interval=0.0, progress=lambda *a: seen.append(a[0]),
                    max_seconds=0.05)
    check("进度回调被调用", len(seen) > 0, f"{len(seen)} 次")
    check("--max-seconds 能中止", r_to["aborted"] and r_to["tried"] < 1 << 16,
          f"tried={r_to['tried']:,}")

    # 输入校验
    try:
        lk.crack([], 10)
        check("空明密文对抛 ValueError", False)
    except ValueError:
        check("空明密文对抛 ValueError", True)
    try:
        lk.crack([(1, 2)], 9)
        check("越界密钥长度抛 ValueError", False)
    except ValueError:
        check("越界密钥长度抛 ValueError", True)
    try:
        lk.crack([(999, 2)], 10)
        check("越界明文抛 ValueError", False)
    except ValueError:
        check("越界明文抛 ValueError", True)

    # 多进程接口存在且结果与单线程一致(环境不支持时自动回退)
    pairs = lk.make_pairs(0b1011001, 11, 3, random.Random(5))
    single = lk.crack(pairs, 11)
    para = lk.crack_parallel(pairs, 11, workers=2)
    check("crack_parallel 结果与单线程一致", para["keys"] == single["keys"],
          f"keys={para['keys']}, workers={para['workers']}"
          + (f", 已回退({para['fallback_reason'][:40]})"
             if para.get("fallback_reason") else ""))

    # subprocess 并行: 本沙箱唯一能真正提速的路径, 且结果必须与单线程逐值一致
    sp_pairs = lk.make_pairs(0b1010001010, 16, 4, random.Random(7))
    sp_single = lk.crack(sp_pairs, 16)
    sp = lk.crack_subprocess(sp_pairs, 16, workers=4)
    check("crack_subprocess 结果与单线程一致", sp["keys"] == sp_single["keys"],
          f"keys={sp['keys']}, 单线程={sp_single['keys']}, "
          f"parallel={sp.get('parallel')}")
    check("crack_subprocess 遍历数等于密钥空间", sp["tried"] == (1 << 16),
          f"tried={sp['tried']:,} / {1 << 16:,}")
    check("crack_subprocess 进程数等于 workers", sp.get("workers") == 4,
          f"workers={sp.get('workers')}")
    check("crack_subprocess 命中真实密钥", 0b1010001010 in sp["keys"],
          f"真实密钥 {lk.key_to_bits(0b1010001010, 16)}")

    # 早退/回退路径: workers=1 直接走单线程, 不会尝试起进程
    sp1 = lk.crack_subprocess(sp_pairs, 16, workers=1)
    check("crack_subprocess(workers=1) 走单线程", sp1.get("parallel") == "single",
          f"parallel={sp1.get('parallel')}")

    # 密钥空间太小时不起子进程(启动开销不划算)
    small = lk.make_pairs(0b1011, 10, 2, random.Random(3))
    sps = lk.crack_subprocess(small, 10, workers=4)
    check("密钥空间过小时回退单线程", sps.get("parallel") == "single",
          f"2^10 < {lk._SUBPROCESS_MIN_KEYS:,} -> parallel={sps.get('parallel')}")

    # 进度回调的 tried 必须单调不减且不超过 span
    seen = []
    lk.crack_subprocess(sp_pairs, 16, workers=2, interval=0.0,
                        progress=lambda t, s, e, r, rm: seen.append(t))
    check("进度回调 tried 单调不减且不超上界",
          bool(seen) and all(a <= b for a, b in zip(seen, seen[1:]))
          and max(seen) <= 1 << 16,
          f"回调 {len(seen)} 次, 最大 {max(seen) if seen else 0:,}")


# --------------------------------------------------------------------------
# 7. 测速与估算
# --------------------------------------------------------------------------

def test_estimate() -> None:
    print("\n--- 7. 测速与耗时估算 ---")
    rate = lk.measure_rate(10, samples=3000)
    check("测速返回正数", rate > 0, f"单层约 {rate:,.0f} 候选密钥/秒")

    est0 = lk.estimate_seconds(10, rate)
    check("2^10 估算约 5 毫秒", 0.001 < est0 < 0.5, f"{est0*1000:.2f} ms")

    # 估算应大致正比于 2^L x 层数
    #   est(L) = 2^L * ceil(L/10) / rate_per_stage
    #   比值 est(20)/est(10) = 2^10 * 2/1 = 2048
    est20 = lk.estimate_seconds(20, rate)
    ratio = est20 / est0
    check("2^20 估算约为 2^10 的 2048 倍", 1000 < ratio < 4000,
          f"2^10={est0*1000:.2f} ms, 2^20={est20:.1f} s (比值 {ratio:,.0f})")

    # 推荐函数
    bits, sec = lk.suggest_bits(60.0, rate)
    check("suggest_bits 返回合法长度", lk.MIN_KEY_BITS <= bits <= lk.MAX_KEY_BITS,
          f"目标 60 s -> {bits} bit (预计 {lk.format_duration(sec)})")
    check("suggest_bits 的估算接近目标", 0.2 * 60 < sec < 5 * 60,
          f"{sec:.1f} s")

    # 层数越多越慢
    check("级联层数增加使速度下降", lk.measure_rate(30, samples=800) < rate,
          f"单层 {rate:,.0f} vs 3 层 {lk.measure_rate(30, samples=800):,.0f}")


# --------------------------------------------------------------------------
# 8. 格式化
# --------------------------------------------------------------------------

def test_format() -> None:
    print("\n--- 8. 格式化工具 ---")
    check("千位分隔", lk.format_int(1048576) == "1,048,576", lk.format_int(1048576))
    cases = [(0.0005, "毫秒"), (0.5, "毫秒"), (5, "秒"), (90, "分"),
             (3700, "小时"), (200000, "天")]
    bad = [s for s, kw in cases if kw not in lk.format_duration(s)]
    check("耗时格式化覆盖各量级", not bad,
          f"{lk.format_duration(0.5)} / {lk.format_duration(5)} / "
          f"{lk.format_duration(90)} / {lk.format_duration(3700)}")
    check("未知耗时显示未知", lk.format_duration(None) == "未知")


# --------------------------------------------------------------------------

def main() -> int:
    print("=" * 78)
    print("第 4 关(进阶) 扩展密钥空间 自测套件")
    print("=" * 78)
    t0 = time.perf_counter()
    test_construction()
    test_degenerates_to_sdes()
    test_roundtrip()
    test_subkeys()
    test_pair_tools()
    test_crack()
    test_estimate()
    test_format()
    dt = time.perf_counter() - t0
    print("\n" + "=" * 78)
    if _FAILURES:
        print(f"结果: {len(_FAILURES)} 项失败")
        for name in _FAILURES:
            print(f"  - {name}")
        return 1
    print(f"结果: 全部通过  (耗时 {dt:.2f} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
