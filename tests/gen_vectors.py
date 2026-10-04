#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""独立第二实现 · 交叉测试向量生成器（第 2 关 / 交叉测试）

为什么需要这个文件
------------------
第 2 关要求「两个相互独立的程序」对同一批 (明文, 密钥) 得到相同的密文。
如果两次都用本项目的 sdes.core 生成，那只能证明程序可复现，
并不能证明算法实现正确 —— 因此本文件**刻意不 import sdes 包的任何代码**，
置换表与运算流程按作业文档重新抄写一遍，充当"对方的程序"。

生成的 CSV 与网页版 / 桌面版第 2 关的格式完全一致：

    pt,key,ct
    10010101,0001011100,01100001
    11100000,0111101011,01010111
    ...

用法
----
    python -m tests.gen_vectors                          # 200 条随机密钥, 输出到屏幕
    python -m tests.gen_vectors -n 200 -o 对方.csv        # 写入文件
    python -m tests.gen_vectors -n 100 --key 1010000010 -o 对方.csv
    python -m tests.gen_vectors -o 对方.csv --check       # 顺便与本项目 sdes.core 比对

配合网页版第 2 关（单人交叉测试的截图流程）：
    1. 网页点「生成测试向量」(默认 200 条, 种子 20261008)
    2. 点「选择对方 CSV 文件…」选本工具生成的 CSV（或把内容粘进下面的框）
    3. 点「比对」→ 得到「一致 N/N 行」

取样序列说明：明文与随机密钥的生成顺序与网页版严格一致（同一个固定种子
20261008、同一套随机数调用次序），所以 pt / key 两列必然相同，
真正被独立计算、用来互相校验的是 ct 列。
"""

from __future__ import annotations

import argparse
import random
import sys

# ---------------------------------------------------------------------------
# 转换单元 —— 按作业文档独立抄写（1-indexed, 最左位为位置 1）
# ---------------------------------------------------------------------------

BLOCK_BITS = 8
KEY_BITS = 10
VECTOR_SEED = 20261008

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
SPBOX = (2, 4, 3, 1)
SBOX1 = ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2))
SBOX2 = ((0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3))


def perm(bits: str, table) -> str:
    """按置换表重排: 输出第 i 位 = 输入第 table[i] 位。"""
    return "".join(bits[i - 1] for i in table)


def left_shift(bits: str, n: int) -> str:
    """循环左移 n 位。"""
    n %= len(bits)
    return bits[n:] + bits[:n]


def xor(a: str, b: str) -> str:
    """逐位异或。"""
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def sbox(bits: str, box) -> str:
    """S 盒查表: 行 = 第 1、4 位, 列 = 第 2、3 位。"""
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(box[row][col], "02b")


def f(right: str, subkey: str) -> str:
    """轮函数 F: EP 扩展 -> 与子密钥异或 -> 两个 S 盒 -> SPBox 置换。"""
    x = xor(perm(right, EP), subkey)
    return perm(sbox(x[:4], SBOX1) + sbox(x[4:], SBOX2), SPBOX)


def fk(bits: str, subkey: str) -> str:
    """f_K(L, R) = (L xor F(R, K), R)"""
    left, right = bits[:4], bits[4:]
    return xor(left, f(right, subkey)) + right


def key_schedule(key: str) -> tuple:
    """密钥扩展: K_i = P8(Shift^i(P10(K))), i = 1, 2（与作业文档定义一致）。"""
    p10 = perm(key, P10)
    left, right = p10[:5], p10[5:]
    left, right = left_shift(left, 1), left_shift(right, 1)
    k1 = perm(left + right, P8)
    k2 = perm(left_shift(left, 2) + left_shift(right, 2), P8)
    return k1, k2


def encrypt(plaintext: str, key: str) -> str:
    """加密: C = IP^-1( f_K2( SW( f_K1( IP(P) ) ) ) )"""
    k1, k2 = key_schedule(key)
    state = fk(perm(plaintext, IP), k1)
    state = state[4:] + state[:4]          # SW: 左右 4 位互换
    state = fk(state, k2)
    return perm(state, IP_INV)


# ---------------------------------------------------------------------------
# 向量取样（与网页版 api_vectors 的随机数调用次序保持一致）
# ---------------------------------------------------------------------------

def build_rows(count: int, fixed_key: str | None = None) -> list:
    """生成 count 条 (pt, key, ct)，ct 由本文件的独立实现计算。"""
    rng = random.Random(VECTOR_SEED)
    rows = []
    for _ in range(count):
        p = rng.randrange(1 << BLOCK_BITS)
        if fixed_key:
            k = fixed_key
        else:
            k = format(rng.randrange(1 << KEY_BITS), f"0{KEY_BITS}b")
        pt = format(p, f"0{BLOCK_BITS}b")
        rows.append((pt, k, encrypt(pt, k)))
    return rows


def to_csv(rows) -> str:
    """输出与网页版/桌面版完全相同的 CSV 文本。"""
    return "pt,key,ct\n" + "\n".join(f"{pt},{key},{ct}" for pt, key, ct in rows) + "\n"


# ---------------------------------------------------------------------------
# 可选自检：与本项目 sdes.core 对照
# ---------------------------------------------------------------------------

def check_against_core(rows) -> int:
    """把本文件的密文与 sdes.core 的密文逐条比对，返回不一致条数。"""
    try:
        from sdes import core
    except ImportError:
        print("[!] 找不到 sdes 包，请在项目根目录运行。", file=sys.stderr)
        return -1

    mismatch = 0
    first = None
    for pt, key, ct in rows:
        ref = core.encrypt(pt, key)
        if ref != ct:
            mismatch += 1
            if first is None:
                first = (pt, key, ct, ref)

    print(f"[自检] {len(rows)} 条向量与 sdes.core 比对: "
          f"{'全部一致' if mismatch == 0 else f'{mismatch} 条不一致'}",
          file=sys.stderr)
    if first is not None:
        pt, key, ct, ref = first
        print(f"[自检] 首条差异: pt={pt} key={key} 本文件={ct} core={ref}", file=sys.stderr)
    return mismatch


# ---------------------------------------------------------------------------
# 命令行
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tests.gen_vectors",
        description="用独立第二实现生成第 2 关交叉测试向量 CSV",
    )
    parser.add_argument("-n", "--count", type=int, default=200, help="生成条数, 默认 200")
    parser.add_argument("--key", default="", help="固定 10-bit 密钥, 留空表示随机")
    parser.add_argument("-o", "--out", default="", help="输出文件, 留空则打印到屏幕")
    parser.add_argument("--check", action="store_true",
                        help="顺便与本项目 sdes.core 逐条比对并打印结论")
    args = parser.parse_args(argv)

    if not 1 <= args.count <= 5000:
        print("[!] 条数需在 1~5000 之间。", file=sys.stderr)
        return 1

    fixed_key = args.key.strip() or None
    if fixed_key is not None and (len(fixed_key) != KEY_BITS or set(fixed_key) - set("01")):
        print(f"[!] 密钥必须是 {KEY_BITS} 个 0/1 字符, 当前 {fixed_key!r}", file=sys.stderr)
        return 1

    rows = build_rows(args.count, fixed_key)
    text = to_csv(rows)

    if args.out:
        with open(args.out, "w", encoding="utf-8-sig", newline="") as fp:
            fp.write(text)
        print(f"[+] 已写入 {args.out}: {len(rows)} 条向量 "
              f"(种子 {VECTOR_SEED}, 密钥{'固定为 ' + fixed_key if fixed_key else '随机'})")
        print("[i] 下一步: 网页版第 2 关 -> 生成测试向量 -> 选择对方 CSV 文件 -> 比对",
              file=sys.stderr)
    else:
        sys.stdout.write(text)

    if args.check:
        if check_against_core(rows) != 0:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
