"""第 4 关(暴力破解) 与 第 5 关(密钥碰撞封闭测试)。

第 4 关思路
-----------
S-DES 密钥空间仅 2^10 = 1024, 已知明文-密文对即可穷举。
单对 8-bit 明文/密文平均留下 1024/256 ≈ 4 个候选密钥;
两对几乎唯一确定(期望候选 ≈ 1 + 1023/2^16 ≈ 1.016)。

本模块提供单线程与多线程两种实现, 便于对比加速比(作业要求"多线程方式
提升破解效率")。两种实现走的是同一套 core.encrypt_int, 结果必然一致。
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .core import KEY_BITS, decrypt_int, encrypt_int

_KEY_SPACE = 1 << KEY_BITS          # 1024
_BLOCK_SPACE = 1 << 8               # 256


# ---------------------------------------------------------------------------
# 第 4 关: 暴力破解
# ---------------------------------------------------------------------------

def brute_force(pairs, *, want_all: bool = True,
                progress=None) -> dict:
    """单线程穷举密钥空间。

    参数
    ----
    pairs : [(plaintext, ciphertext), ...]
        明文/密文可以是 8-bit '0'/'1' 字符串或整数(0~255)。
    want_all : True 返回全部候选密钥; False 找到第一个就停。
    progress : 可选回调 progress(done, total)。

    返回
    ----
    {"keys": [int, ...], "tried": int, "elapsed": float, "rate": float}
    """
    tests = _normalize_pairs(pairs)
    keys: list = []
    t0 = time.perf_counter()
    tried = 0
    for candidate in range(_KEY_SPACE):
        tried += 1
        if _matches(candidate, tests):
            keys.append(candidate)
            if not want_all:
                break
        if progress and (tried & 0xFF) == 0:
            progress(tried, _KEY_SPACE)
    elapsed = time.perf_counter() - t0
    if progress:
        progress(tried, _KEY_SPACE)
    return {"keys": keys, "tried": tried, "elapsed": elapsed,
            "rate": tried / elapsed if elapsed > 0 else float("inf")}


def brute_force_threaded(pairs, *, workers: int = 4, chunk: int = 64,
                         want_all: bool = True) -> dict:
    """多线程穷举。

    把 1024 个候选密钥按 chunk 大小切片, 由线程池并行处理,
    用锁保护结果列表, want_all=False 时通过 Event 提前终止。
    """
    tests = _normalize_pairs(pairs)
    workers = max(1, int(workers))
    chunk = max(1, int(chunk))

    found: list = []
    lock = threading.Lock()
    stop = threading.Event()
    counter = {"tried": 0}

    def scan(start: int, end: int) -> int:
        local_found: list = []
        tried = 0
        for candidate in range(start, end):
            tried += 1
            if stop.is_set():
                break
            if _matches(candidate, tests):
                local_found.append(candidate)
                if not want_all:
                    stop.set()
                    break
        with lock:
            found.extend(local_found)
            counter["tried"] += tried
        return tried

    ranges = [(s, min(s + chunk, _KEY_SPACE))
              for s in range(0, _KEY_SPACE, chunk)]

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda r: scan(*r), ranges))
    elapsed = time.perf_counter() - t0

    return {"keys": sorted(found), "tried": counter["tried"], "elapsed": elapsed,
            "rate": counter["tried"] / elapsed if elapsed > 0 else float("inf"),
            "workers": workers, "chunks": len(ranges)}


def _normalize_pairs(pairs):
    """把输入统一成 [(int_pt, int_ct), ...]。"""
    if not pairs:
        raise ValueError("至少需要一个明文-密文对")
    out = []
    for pt, ct in pairs:
        p = int(pt, 2) if isinstance(pt, str) else int(pt)
        c = int(ct, 2) if isinstance(ct, str) else int(ct)
        if not 0 <= p < _BLOCK_SPACE or not 0 <= c < _BLOCK_SPACE:
            raise ValueError(f"明文/密文必须是 8-bit: {pt!r}, {ct!r}")
        out.append((p, c))
    return out


def _matches(candidate: int, tests) -> bool:
    """候选密钥是否满足全部明文-密文对。"""
    for p, c in tests:
        if encrypt_int(p, candidate) != c:
            return False
    return True


def brute_force_by_key(key: str, plaintext: str) -> dict:
    """演示用: 已知真实密钥, 生成一对样本再破解它。"""
    from .core import validate_block, validate_key
    k = validate_key(key)
    p = validate_block(plaintext)
    c = encrypt_int(p, k)
    result = brute_force_threaded([(p, c)])
    result["truth"] = k
    result["plaintext"] = p
    result["ciphertext"] = c
    result["contains_truth"] = k in result["keys"]
    return result


# ---------------------------------------------------------------------------
# 第 5 关: 密钥碰撞 / 封闭测试
# ---------------------------------------------------------------------------

def equivalent_key_classes() -> list:
    """返回"真正等价"的密钥等价类 —— 对全部 1024 个主密钥, 按其 (K1, K2) 分组。

    结论: 本算法**不存在**这样的等价类, 因此恒返回空列表。理由:
    K1 由 P10 输出的左半 5 位经 1 位左移后取第 3、4、5 位构成, 丢弃第 1、2 位;
    但 K2 是在左移 2 位之后取同一组位置 (即原来的第 1、2 位又被取到),
    所以左半 5 位在 K1 与 K2 中都至少被用到一次; 右半 5 位在两个子密钥中
    始终被使用。于是没有任何密钥比特是全程冗余的, 1024 个主密钥一一对应
    到 1024 个不同的 (K1, K2), 不存在行为完全相同的主密钥。

    真正存在的是**针对特定明文**的碰撞(多密钥 -> 同一密文), 那由
    :func:`analyze_collisions` 统计, 与这里的"全局等价"是两回事。
    """
    from .core import key_schedule
    groups: dict = {}
    for k in range(_KEY_SPACE):
        k1, k2 = key_schedule(k)
        groups.setdefault((k1, k2), []).append(k)
    return [sorted(v) for v in groups.values() if len(v) > 1]


def analyze_collisions(*, progress=None) -> dict:
    """枚举全部 1024 个密钥 x 256 个明文, 统计密文碰撞情况。

    这是第 5 关的封闭测试: 明文空间 256、密钥空间 1024, 由鸽巢原理
    对任一明文必存在多个密钥给出同一密文。

    返回
    ----
    {
      "table": {plaintext: {ciphertext: [keys]}},   # 完整映射
      "per_plaintext": {plaintext: {"max": , "avg_keys_per_cipher": }},
      "buckets":          密文桶大小的分布 {桶大小: 桶个数},
      "max_bucket":       最大的"多密钥同密文"桶大小,
      "total_pairs":      1024*256,
      "distinct_per_pt":  每个明文的平均不同密文数(应 = 256),
    }
    """
    from .core import key_schedule

    table: dict = {}
    total = _KEY_SPACE * _BLOCK_SPACE
    done = 0
    for k in range(_KEY_SPACE):
        for p in range(_BLOCK_SPACE):
            c = encrypt_int(p, k)
            table.setdefault(p, {}).setdefault(c, []).append(k)
        done += _BLOCK_SPACE
        if progress:
            progress(done, total)

    per_plaintext: dict = {}
    bucket_hist: dict = {}
    max_bucket = 0
    for p, row in table.items():
        sizes = [len(v) for v in row.values()]
        distinct = len(row)
        per_plaintext[p] = {
            "max": max(sizes) if sizes else 0,
            "avg_keys_per_cipher": (_KEY_SPACE / distinct) if distinct else 0.0,
            "distinct": distinct,
        }
        for s in sizes:
            bucket_hist[s] = bucket_hist.get(s, 0) + 1
            max_bucket = max(max_bucket, s)

    return {
        "table": table,
        "per_plaintext": per_plaintext,
        "buckets": bucket_hist,
        "max_bucket": max_bucket,
        "total_pairs": total,
        "distinct_per_pt": sum(v["distinct"] for v in per_plaintext.values()) / len(per_plaintext),
    }


def collision_report(sample_plaintext: int = 0) -> str:
    """生成可读的第 5 关分析报告(纯文本)。"""
    info = analyze_collisions()
    lines = []
    lines.append("=" * 68)
    lines.append("第 5 关: 密钥碰撞 / 封闭测试分析")
    lines.append("=" * 68)
    lines.append(f"密钥空间 = 2^10 = {_KEY_SPACE}, 明文空间 = 2^8 = {_BLOCK_SPACE}")
    lines.append(f"全部 (密钥, 明文) 组合 = {info['total_pairs']}")
    lines.append(f"每个明文的平均不同密文数 = {info['distinct_per_pt']:.2f} (上限 {_BLOCK_SPACE})")
    lines.append(f"最大 [多密钥->同一密文] 桶大小 = {info['max_bucket']} 个密钥")
    lines.append("")
    lines.append("密文桶大小分布 (桶大小: 出现次数):")
    for size in sorted(info["buckets"]):
        lines.append(f"  大小 {size:>3} : {info['buckets'][size]:>6} 个")
    lines.append("")
    sample = info["table"].get(sample_plaintext, {})
    multi = {c: ks for c, ks in sample.items() if len(ks) > 1}
    lines.append(f"明文 P = {sample_plaintext:08b} 时的碰撞样例(共 {len(multi)} 个密文有多于 1 个密钥):")
    shown = 0
    for c in sorted(multi):
        lines.append(f"  密文 C = {c:08b}  <-  密钥 {['{:010b}'.format(k) for k in multi[c]]}")
        shown += 1
        if shown >= 8:
            lines.append("  ... (仅显示前 8 条)")
            break
    lines.append("")
    classes = equivalent_key_classes()
    if classes:
        lines.append(f"完全等价的密钥类 (对全部明文行为相同), 共 {len(classes)} 类:")
        for grp in classes[:10]:
            lines.append("  " + ", ".join("{:010b}".format(k) for k in grp))
        if len(classes) > 10:
            lines.append(f"  ... (共 {len(classes)} 类)")
    else:
        lines.append("没有完全等价的密钥类。")
    lines.append("")
    lines.append("结论:")
    lines.append("  1) 密钥空间(1024) > 明文空间(256), 由鸽巢原理, 对任一明文必存在")
    lines.append("     多个密钥映射到同一密文, 即存在 K_i != K_j 使 E(K_i,P) = E(K_j,P)。")
    lines.append("  2) 因此仅凭单组明文-密文无法唯一确定密钥, 暴力破解平均得到约 4 个候选。")
    lines.append("  3) 增加明文-密文对数量可快速收敛: 两对时期望候选约 1.016 个。")
    lines.append("=" * 68)
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "report":
        print(collision_report())
    else:
        demo = brute_force_by_key("1010000010", "10010111")
        print(f"真实密钥 = {demo['truth']:010b}")
        print(f"密文     = {demo['ciphertext']:08b}")
        print(f"候选密钥 = {['{:010b}'.format(k) for k in demo['keys']]}")
        print(f"命中真实 = {demo['contains_truth']}, 耗时 {demo['elapsed'] * 1000:.2f} ms")
