"""第 4 关暴力破解性能基准（单线程 vs 多线程）。

用法（必须在项目根目录执行）::

    python -m tests.bench_crack
    python -m tests.bench_crack --repeat 15
    python -m tests.bench_crack --pairs 2

为什么要单独做基准：`tests/test_all.py` 里也打印了一次耗时，但那是**单次采样**，
运行间抖动很大（几毫秒量级）。本脚本重复多次并取**中位数**，用于文档与测试报告
中给出可复现的数字。

结论提示：CPython 的 GIL 使纯 Python 计算无法真正并行，而 S-DES 密钥空间只有
1024 个（单线程一次完整穷举约 5 ms），因此线程版本只会增加分块与合并开销，
比单线程更慢。`brute_force_threaded` 的价值在于结果与单线程严格一致。

真正的并行请用 `sdes/longkey.py` 的 `crack_subprocess`（子进程 + 文件传结果）。
不用 `multiprocessing` 是因为它依赖命名管道，受限环境下会被拒绝。
"""

from __future__ import annotations

import argparse
import statistics
import time

from sdes.core import encrypt_int, validate_key
from sdes.crack import analyze_collisions, brute_force, brute_force_threaded

TRUTH = "1010000010"
PLAINTEXT = "10010111"


def _make_pairs(count: int) -> list[tuple[int, int]]:
    """由已知密钥造出 `count` 组明密文对。

    首组固定使用 PLAINTEXT（与 `tests/test_all.py` 的用例一致），
    其余组使用紧随其后的明文，以便第 2 组能快速收敛到唯一密钥。
    """
    key = validate_key(TRUTH)
    start = int(PLAINTEXT, 2)
    return [((start + i) & 0xFF, encrypt_int((start + i) & 0xFF, key)) for i in range(count)]


def _timeit(func, repeat: int) -> float:
    """调用 func repeat 次，返回耗时的中位数（毫秒）。"""
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        func()
        samples.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(samples)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="第4关暴力破解性能基准")
    parser.add_argument("--repeat", type=int, default=15, help="每个配置的重复次数（取中位数），默认 15")
    parser.add_argument("--pairs", type=int, default=1, help="参与约束的明密文对数量，默认 1")
    parser.add_argument("--chunk", type=int, default=64, help="多线程分块大小，默认 64")
    parser.add_argument(
        "--workers",
        type=int,
        nargs="*",
        default=[1, 2, 4, 8, 16],
        help="要测试的线程数列表，默认 1 2 4 8 16",
    )
    args = parser.parse_args(argv)

    pairs = _make_pairs(max(1, args.pairs))

    print("=" * 68)
    print("第 4 关暴力破解性能基准（中位数）")
    print("=" * 68)
    print(f"真实密钥     : {TRUTH}")
    print(f"明密文对数量 : {len(pairs)}")
    print(f"重复次数     : {args.repeat}（取中位数）")
    print(f"分块大小     : {args.chunk}")
    print("-" * 68)

    single = _timeit(lambda: brute_force(pairs), args.repeat)
    result = brute_force(pairs)
    print(f"单线程 brute_force          : {single:8.3f} ms   "
          f"候选 {len(result['keys'])} 个  遍历 {result['tried']} 个密钥")

    table = []
    for workers in args.workers:
        med = _timeit(
            lambda w=workers: brute_force_threaded(pairs, workers=w, chunk=args.chunk),
            args.repeat,
        )
        res = brute_force_threaded(pairs, workers=workers, chunk=args.chunk)
        same = sorted(res["keys"]) == sorted(result["keys"])
        table.append((workers, med, same))
        flag = "一致" if same else "!! 不一致 !!"
        print(f"多线程 workers={workers:<3d}          : {med:8.3f} ms   候选集合 {flag}")

    print("-" * 68)
    fastest = min(table, key=lambda row: row[1])
    print(f"最快配置     : workers={fastest[0]}  {fastest[1]:.3f} ms")
    print(f"单线程为基准 : {single:.3f} ms")
    print()
    print("结论：多线程在本算法规模下不占优势 —— 密钥空间仅 1024 个，")
    print("      单线程完整穷举约 5 ms，CPython GIL 使纯 Python 计算无法真正并行，")
    print("      线程只增加分块/合并开销。真正并行见 sdes/longkey.py 的 crack_subprocess")

    print("-" * 68)
    start = time.perf_counter()
    stats = analyze_collisions()
    elapsed = (time.perf_counter() - start) * 1000.0
    print(f"第 5 关 analyze_collisions   : {elapsed:8.1f} ms   "
          f"枚举 {stats['total_pairs']} 对  最大桶 {stats['max_bucket']} 个密钥")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
