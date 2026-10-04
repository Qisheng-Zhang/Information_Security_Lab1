# -*- coding: utf-8 -*-
"""第 4 关(进阶) · 扩展密钥空间: S-DES 级联

作业给定的 S-DES 密钥只有 **10 bit**(密钥空间 1024), 单线程穷举不到 5 毫秒
就能跑完, 无法满足作业第 4 关的要求::

    请设定时间戳, 用视频或动图展示你在多长时间内完成了暴力破解。

本模块在**不改动 S-DES 算法本身**的前提下扩大密钥空间: 把若干个 S-DES 实例
**级联**成乘积密码, 用 L bit 主密钥驱动 ``ceil(L / 10)`` 个 10-bit 子密钥::

    子密钥_i = rotl(K, 10*i) 的高 10 位,   i = 0, 1, ..., ceil(L/10) - 1
    加密:    C = E_{s_{n-1}}( ... E_{s_1}( E_{s_0}(P) ) ... )
    解密:    P = D_{s_0}( ... D_{s_{n-2}}( D_{s_{n-1}}(C) ) ... )

每个主密钥比特至少出现在一个子密钥中, 因此主密钥与子密钥组一一对应,
密钥空间恰好是 **2^L**, 暴力破解的搜索空间随 L 指数增长。

``L = 10`` 时退化为标准 S-DES(单层), 与本项目 ``sdes/core.py`` 的结果完全一致。

用法::

    python -m sdes.longkey                      # 默认 20 bit, 约 10 秒
    python -m sdes.longkey --bits 22            # 约 1 分钟, 适合录视频
    python -m sdes.longkey --bits 23            # 约 2 分钟
    python -m sdes.longkey --table              # 打印各密钥长度的耗时标定表
    python -m sdes.longkey --for-seconds 120    # 让程序推荐合适的 --bits
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from .core import BLOCK_BITS, KEY_BITS, decrypt_int, encrypt_int, int_to_bits

__all__ = [
    "MIN_KEY_BITS", "MAX_KEY_BITS", "DEFAULT_KEY_BITS",
    "subkey_count", "keyspace_size", "key_to_bits", "bits_to_key",
    "subkeys_from_key", "subkeys_from_string",
    "encrypt_ext", "decrypt_ext", "encrypt_ext_bits", "decrypt_ext_bits",
    "random_key", "make_pairs", "verify_key",
    "measure_rate", "estimate_seconds", "suggest_bits",
    "crack", "crack_parallel", "crack_subprocess",
    "format_int", "format_duration",
]

#: 允许的密钥长度范围 (bit)。10 = 标准 S-DES; 上限 40 只是防止误输入天文数字。
MIN_KEY_BITS = 10
MAX_KEY_BITS = 40

#: 默认密钥长度。22 bit 约 1 分钟, 足够录制一段完整的破解视频。
#: 想快速自测可显式用 ``--bits 20``(约 11 秒)或 ``--bits 10``(5 毫秒)。
DEFAULT_KEY_BITS = 22

#: 候选密钥少于此数时不值得起子进程(解释器启动开销占主导), 直接单线程。
_SUBPROCESS_MIN_KEYS = 1 << 16          # 65536

_BLOCK_MASK = (1 << BLOCK_BITS) - 1


def _project_root() -> Path:
    """项目根目录(``sdes`` 包的上一级), 子进程需要它来 ``import sdes``。"""
    return Path(__file__).resolve().parents[1]


#: 子进程 worker 的源码。单独起进程、结果写文件, **不走管道** —— 因为部分沙箱
#: (含 DSH 的 restricted 模式)禁止创建命名管道, ``multiprocessing`` 会直接失败。
#:
#: worker 负责 ``[start, stop)`` 一整段, 内部再切小节, **每完成一小节就把进度
#: 覆盖写回 out 文件**(单次 json.dump 很小, 开销可忽略), 这样父进程只是周期性
#: 读文件就能拿到平滑的进度, 而进程数恒等于 ``--workers``。
_WORKER_SRC = '''# -*- coding: utf-8 -*-
"""sdes.longkey 的并行 worker: 扫描 [start, stop) 并把进度/结果写到 out。"""
import json
import os
import sys

sys.path.insert(0, sys.argv[1])
from sdes import longkey as lk        # noqa: E402

with open(sys.argv[2], encoding="utf-8") as fh:
    job = json.load(fh)
pairs = [(int(p), int(c)) for p, c in job["pairs"]]
key_bits = int(job["key_bits"])
start, stop = int(job["start"]), int(job["stop"])
out = job["out"]
slice_size = max(1, int(job.get("slice", 65536)))

keys = []
tried = start
while tried < stop:
    end = min(tried + slice_size, stop)
    hits, n = lk._scan_range((tried, end, key_bits, pairs))
    keys.extend(int(k) for k in hits)
    tried = end
    # 覆盖写: 父进程读到的永远是"到目前为止"的累计值。
    # 注意 tried 写的是**本段内已完成的条数**(tried - start), 父进程直接相加即可。
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"keys": keys, "tried": tried - start, "done": False}, fh)
    os.replace(tmp, out)
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"keys": keys, "tried": tried - start, "done": True}, fh)
'''


# --------------------------------------------------------------------------
# 格式化小工具
# --------------------------------------------------------------------------

def format_int(value: float) -> str:
    """给整数加千位分隔符; 非整数就退化成取整。"""
    return f"{int(value):,}"


def format_duration(seconds: float | None) -> str:
    """把秒数格式化成中文可读形式。``None`` 表示未知。"""
    if seconds is None:
        return "未知"
    if seconds < 0:
        return "0 毫秒"
    if seconds < 1:
        return f"{seconds * 1000:.0f} 毫秒"
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m} 分 {s:02d} 秒"
    if seconds < 86400:
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h} 小时 {m:02d} 分 {s:02d} 秒"
    d, rem = divmod(int(seconds), 86400)
    h = rem // 3600
    return f"{d} 天 {h} 小时"


def _ts() -> str:
    """当前时刻 ``HH:MM:SS``, 用于给视频留下时间戳证据。"""
    return datetime.now().strftime("%H:%M:%S")


# --------------------------------------------------------------------------
# 密钥 <-> 子密钥
# --------------------------------------------------------------------------

def subkey_count(key_bits: int) -> int:
    """L bit 主密钥需要多少个 10-bit 子密钥(级联层数)。"""
    _check_key_bits(key_bits)
    return -(-key_bits // KEY_BITS)          # 向上取整


def keyspace_size(key_bits: int) -> int:
    """主密钥空间大小 ``2**L``。"""
    _check_key_bits(key_bits)
    return 1 << key_bits


def _check_key_bits(key_bits: int) -> None:
    if not isinstance(key_bits, int):
        raise TypeError(f"密钥长度必须是整数, 收到 {type(key_bits).__name__}")
    if not MIN_KEY_BITS <= key_bits <= MAX_KEY_BITS:
        raise ValueError(
            f"密钥长度必须在 {MIN_KEY_BITS}~{MAX_KEY_BITS} bit 之间, "
            f"收到 {key_bits}")


def key_to_bits(key_int: int, key_bits: int) -> str:
    """主密钥整数 -> ``key_bits`` 位 0/1 字符串(左补零)。"""
    _check_key_bits(key_bits)
    return int_to_bits(key_int, key_bits)


def bits_to_key(key_str: str) -> tuple[int, int]:
    """0/1 字符串 -> ``(密钥整数, 位长)``。"""
    s = "".join(ch for ch in str(key_str) if ch not in " \t_")
    if not s or set(s) - set("01"):
        raise ValueError(f"密钥只能包含 0 和 1, 收到 {key_str!r}")
    return int(s, 2), len(s)


def _rotate_left(value: int, shift: int, width: int) -> int:
    """把 ``width`` 位的 ``value`` 循环左移 ``shift`` 位。"""
    shift %= width
    if shift == 0:
        return value & ((1 << width) - 1)
    mask = (1 << width) - 1
    return ((value << shift) | (value >> (width - shift))) & mask


def subkeys_from_key(key_int: int, key_bits: int) -> tuple:
    """由主密钥整数推出全部 10-bit 子密钥(级联顺序)。

    第 i 个子密钥取自主密钥中从第 ``10*i`` 位(MSB 起)开始的 10 个连续比特,
    超出末尾则从开头绕回 —— 等价于"循环左移 ``10*i`` 位后取高 10 位"。
    """
    _check_key_bits(key_bits)
    top = key_bits - KEY_BITS
    return tuple(
        _rotate_left(key_int, KEY_BITS * i, key_bits) >> top
        for i in range(subkey_count(key_bits))
    )


def subkeys_from_string(key_str: str) -> tuple:
    """``subkeys_from_key`` 的字符串版本, 只用于测试交叉验证(更直观)。"""
    L = len(key_str)
    _check_key_bits(L)
    doubled = key_str + key_str
    return tuple(
        int(doubled[(KEY_BITS * i) % L:][:KEY_BITS], 2)
        for i in range(subkey_count(L))
    )


# --------------------------------------------------------------------------
# 级联加解密
# --------------------------------------------------------------------------

def encrypt_ext(plain: int, key_int: int, key_bits: int) -> int:
    """用 L bit 主密钥对 8-bit 分组做级联加密, 返回 8-bit 密文。"""
    _check_key_bits(key_bits)
    top = key_bits - KEY_BITS
    mask = (1 << key_bits) - 1
    block = plain & _BLOCK_MASK
    rot = key_int
    for _ in range(subkey_count(key_bits)):
        block = encrypt_int(block, rot >> top)
        rot = ((rot << KEY_BITS) | (rot >> top)) & mask
    return block


def decrypt_ext(cipher: int, key_int: int, key_bits: int) -> int:
    """``encrypt_ext`` 的逆运算(子密钥逆序, 每个用 ``decrypt_int``)。"""
    _check_key_bits(key_bits)
    block = cipher & _BLOCK_MASK
    for sub in reversed(subkeys_from_key(key_int, key_bits)):
        block = decrypt_int(block, sub)
    return block


def encrypt_ext_bits(plain_bits: str, key_int: int, key_bits: int) -> str:
    """8-bit 0/1 字符串接口。"""
    return int_to_bits(encrypt_ext(int(plain_bits, 2), key_int, key_bits),
                       BLOCK_BITS)


def decrypt_ext_bits(cipher_bits: str, key_int: int, key_bits: int) -> str:
    """8-bit 0/1 字符串接口(解密)。"""
    return int_to_bits(decrypt_ext(int(cipher_bits, 2), key_int, key_bits),
                       BLOCK_BITS)


# --------------------------------------------------------------------------
# 挑战数据
# --------------------------------------------------------------------------

def random_key(key_bits: int, rng: random.Random | None = None) -> int:
    """随机生成一个 ``key_bits`` 位主密钥。"""
    _check_key_bits(key_bits)
    rng = rng or random
    return rng.randrange(1 << key_bits)


def default_pairs(key_bits: int) -> int:
    """默认的明文-密文对数量。

    一组 (明文, 密文) 只能把候选密钥缩小到 ``2^L / 2^8``; 要想唯一确定密钥,
    需要 ``8n > L``, 即至少 ``ceil(L/8)`` 组。这里再多给一组留余量。
    """
    _check_key_bits(key_bits)
    return max(2, (key_bits + 7) // 8 + 1)


def make_pairs(key_int: int, key_bits: int, count: int | None = None,
               rng: random.Random | None = None) -> list:
    """生成 ``count`` 组互不相同的 (明文, 密文) 对, 明文随机且不重复。"""
    _check_key_bits(key_bits)
    rng = rng or random
    count = default_pairs(key_bits) if count is None else int(count)
    if count < 1:
        raise ValueError("明文-密文对数量至少为 1")
    if count > 1 << BLOCK_BITS:
        raise ValueError(f"最多只能有 {1 << BLOCK_BITS} 组互不相同的明文")
    seen: set[int] = set()
    pairs = []
    while len(pairs) < count:
        p = rng.randrange(1 << BLOCK_BITS)
        if p in seen:
            continue
        seen.add(p)
        pairs.append((p, encrypt_ext(p, key_int, key_bits)))
    return pairs


def verify_key(pairs, key_int: int, key_bits: int) -> bool:
    """检查某个候选密钥是否能解释全部明文-密文对。"""
    return all(encrypt_ext(p, key_int, key_bits) == c for p, c in pairs)


def _normalize_pairs(pairs) -> list:
    out = []
    for item in pairs:
        if isinstance(item, (tuple, list)) and len(item) == 2:
            p, c = item
        else:
            raise ValueError(f"每个明文-密文对应是 (明文, 密文): {item!r}")
        p, c = int(p), int(c)
        if not (0 <= p < (1 << BLOCK_BITS) and 0 <= c < (1 << BLOCK_BITS)):
            raise ValueError(f"明文/密文必须是 {BLOCK_BITS} bit: {p}, {c}")
        out.append((p, c))
    if not out:
        raise ValueError("至少需要一个明文-密文对")
    return out


# --------------------------------------------------------------------------
# 测速与估算
# --------------------------------------------------------------------------

def measure_rate(key_bits: int, samples: int = 20000,
                 seed: int = 20261008) -> float:
    """粗略测一下单线程每秒能试多少个候选密钥(正比于 ``1/级联层数``)。"""
    _check_key_bits(key_bits)
    rng = random.Random(seed)
    keys = [rng.randrange(1 << key_bits) for _ in range(samples)]
    plain = 0b10010111
    t0 = time.perf_counter()
    for k in keys:
        encrypt_ext(plain, k, key_bits)
    dt = time.perf_counter() - t0
    return samples / dt if dt else float("inf")


def estimate_seconds(key_bits: int, rate_per_stage: float | None = None) -> float:
    """估算单线程穷举完 ``2**L`` 个密钥需要多少秒。

    ``rate_per_stage`` 是**单个 10-bit 层**每秒能试多少个候选密钥(机器的固有速度,
    与 L 无关); 省略时自动测一次。级联 L bit 需要 ``ceil(L/10)`` 层, 每试一个
    候选密钥就要走这么多层, 所以有效速度要除以层数。
    """
    _check_key_bits(key_bits)
    if rate_per_stage is None:
        rate_per_stage = measure_rate(MIN_KEY_BITS)      # 单层速度
    effective = rate_per_stage / subkey_count(key_bits)
    return keyspace_size(key_bits) / effective if effective else float("inf")


def suggest_bits(target_seconds: float,
                 rate_per_stage: float | None = None) -> tuple[int, float]:
    """给定目标耗时, 返回最接近的 ``(key_bits, 预计秒数)``。

    ``rate_per_stage`` 同 ``estimate_seconds``: 单个 10-bit 层的速度。
    """
    if rate_per_stage is None:
        rate_per_stage = measure_rate(MIN_KEY_BITS)
    best = (MIN_KEY_BITS, float("inf"))
    for L in range(MIN_KEY_BITS, MAX_KEY_BITS + 1):
        sec = estimate_seconds(L, rate_per_stage)
        if abs(sec - target_seconds) < abs(best[1] - target_seconds):
            best = (L, sec)
    return best


# --------------------------------------------------------------------------
# 暴力破解
# --------------------------------------------------------------------------

def _cascade_first(pairs_rest, key, key_bits):
    """候选密钥是否通过其余明文-密文对。"""
    return all(encrypt_ext(p, key, key_bits) == c for p, c in pairs_rest)


def crack(pairs, key_bits: int, *, want_all: bool = True, interval: float = 2.0,
          progress=None, max_seconds: float | None = None,
          start_key: int = 0, stop_key: int | None = None) -> dict:
    """单线程穷举扩展密钥空间。

    ``progress(tried, span, elapsed, rate, remaining)`` 每隔 ``interval`` 秒
    被调用一次; ``max_seconds`` 用于给过大的密钥长度兜底(超时返回 ``aborted``)。
    """
    pairs = _normalize_pairs(pairs)
    _check_key_bits(key_bits)
    total = 1 << key_bits
    stop = total if stop_key is None else max(0, min(int(stop_key), total))
    start = max(0, min(int(start_key), stop))
    span = stop - start

    stages = subkey_count(key_bits)
    top = key_bits - KEY_BITS
    kmask = total - 1
    p0, c0 = pairs[0]
    rest = pairs[1:]

    found: list[int] = []
    tried = 0
    aborted = False
    t0 = time.perf_counter()
    last = t0

    for key in range(start, stop):
        rot = key
        block = p0
        for _ in range(stages):
            block = encrypt_int(block, rot >> top)
            rot = ((rot << KEY_BITS) | (rot >> top)) & kmask
        tried += 1
        if block == c0 and _cascade_first(rest, key, key_bits):
            found.append(key)
            if not want_all:
                break
        # 每 8191 次取一次时钟, 避免测时开销拖慢内层循环
        if not (tried & 0x1FFF):
            now = time.perf_counter()
            if progress is not None and now - last >= interval:
                last = now
                elapsed = now - t0
                rate = tried / elapsed if elapsed else 0.0
                progress(tried, span, elapsed, rate,
                         (span - tried) / rate if rate else None)
            if max_seconds is not None and now - t0 >= max_seconds:
                aborted = True
                break

    elapsed = time.perf_counter() - t0
    rate = tried / elapsed if elapsed else 0.0
    return {
        "keys": found,
        "key_bits": key_bits,
        "stages": stages,
        "tried": tried,
        "span": span,
        "total": total,
        "elapsed": elapsed,
        "rate": rate,
        "aborted": aborted,
        "workers": 1,
    }


def _scan_range(job):
    """多进程 worker: 扫描 [start, stop) 并返回 (命中密钥, 试过个数)。"""
    start, stop, key_bits, pairs = job
    stages = subkey_count(key_bits)
    top = key_bits - KEY_BITS
    kmask = (1 << key_bits) - 1
    p0, c0 = pairs[0]
    rest = pairs[1:]
    found = []
    tried = 0
    for key in range(start, stop):
        rot = key
        block = p0
        for _ in range(stages):
            block = encrypt_int(block, rot >> top)
            rot = ((rot << KEY_BITS) | (rot >> top)) & kmask
        tried += 1
        if block == c0 and _cascade_first(rest, key, key_bits):
            found.append(key)
    return found, tried


def crack_parallel(pairs, key_bits: int, *, workers: int = 4,
                   interval: float = 2.0, progress=None,
                   max_seconds: float | None = None) -> dict:
    """多进程穷举(真正并行)。

    纯 Python 受 GIL 限制, **多线程不会提速**, 只有多进程才能并行。若当前环境
    禁止创建子进程(部分沙箱/受限权限), 会自动回退到单线程并在结果里标注。
    """
    pairs = _normalize_pairs(pairs)
    _check_key_bits(key_bits)
    if workers <= 1:
        return crack(pairs, key_bits, interval=interval, progress=progress,
                     max_seconds=max_seconds)

    total = 1 << key_bits
    # 先估一下每个候选要多久, 据此决定分块大小, 让进度大约每秒刷新一次
    try:
        rate = measure_rate(key_bits, samples=4000)
    except Exception:
        rate = 1.0
    per_key = 1.0 / rate if rate else 0.0
    target_chunk = max(4096, int((1.0 / per_key) if per_key else 65536))
    chunks = max(workers * 4, (total + target_chunk - 1) // target_chunk)
    chunks = min(chunks, max(1, total))
    step = -(-total // chunks)
    jobs = [(s, min(s + step, total), key_bits, pairs)
            for s in range(0, total, step)]

    t0 = time.perf_counter()
    found: list[int] = []
    tried = 0
    last = t0
    try:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for hits, n in ex.map(_scan_range, jobs):
                found.extend(hits)
                tried += n
                now = time.perf_counter()
                if max_seconds is not None and now - t0 >= max_seconds:
                    break
                if progress is not None and now - last >= interval:
                    last = now
                    elapsed = now - t0
                    rate_now = tried / elapsed if elapsed else 0.0
                    progress(tried, total, elapsed, rate_now,
                             (total - tried) / rate_now if rate_now else None)
    except Exception as exc:                      # 沙箱/权限禁止创建子进程
        fallback = crack(pairs, key_bits, interval=interval, progress=progress,
                         max_seconds=max_seconds)
        fallback["workers"] = 1
        fallback["fallback_reason"] = f"{type(exc).__name__}: {exc}"
        return fallback

    elapsed = time.perf_counter() - t0
    rate = tried / elapsed if elapsed else 0.0
    return {
        "keys": sorted(found),
        "key_bits": key_bits,
        "stages": subkey_count(key_bits),
        "tried": tried,
        "span": total,
        "total": total,
        "elapsed": elapsed,
        "rate": rate,
        "aborted": tried < total,
        "workers": workers,
    }


# --------------------------------------------------------------------------
# 子进程并行(沙箱里唯一真正能提速的方式)
# --------------------------------------------------------------------------

def _shares(total: int, workers: int):
    """把 ``[0, total)`` 均分成 ``workers`` 段连续区间, 返回 ``[(lo, hi), ...]``。

    **进程数恒等于 workers**: 每段由**一个**子进程从头扫到尾, 段内再切小节上报
    进度。早先的实现按"小块"起进程(1 个进程 = 1 个小块), 在 4 进程/64 块时等于
    启动了 64 个解释器, 光启动开销就把加速比吃光 —— 这是实测出来的真问题。
    """
    workers = max(1, min(workers, total))
    step = -(-total // workers)
    return [(s, min(s + step, total)) for s in range(0, total, step)]


def crack_subprocess(pairs, key_bits: int, *, workers: int = 4,
                     interval: float = 2.0, progress=None,
                     max_seconds: float | None = None,
                     slice_size: int = 65536) -> dict:
    """用 ``subprocess`` 起多个 Python 进程做**真正并行**的穷举。

    为什么不用 ``multiprocessing``: 它靠命名管道传递结果, 而受限沙箱(包括 DSH
    的 restricted 模式)会直接拒绝创建管道, 报 ``PermissionError: [WinError 5]``。
    ``subprocess`` 的子进程把结果写文件, 不碰管道, 因此在本环境可用。

    每个子进程负责 ``[0, total)`` 的一段连续区间, 段内每 ``slice_size`` 个候选
    就把累计进度覆盖写回自己的 ``out_*.json``; 父进程轮询所有 out 文件求和,
    因而 ``progress`` 是平滑的(而不是等整段跑完才跳一次)。

    ``progress(tried, span, elapsed, rate, remaining)`` 每 ``interval`` 秒回调一次。

    任何环节失败(无法建临时目录/起不了进程/子进程异常)都会回退单线程, 并在
    返回值里给出 ``fallback_reason``。
    """
    pairs = _normalize_pairs(pairs)
    _check_key_bits(key_bits)
    total = 1 << key_bits

    if workers <= 1 or total < _SUBPROCESS_MIN_KEYS:
        out = crack(pairs, key_bits, interval=interval, progress=progress,
                    max_seconds=max_seconds)
        out["parallel"] = "single"
        return out

    jobs = _shares(total, workers)
    # 临时目录必须放在项目内: 受限沙箱只允许写工作区, 系统 %TEMP% 会被拒绝。
    # 另外要用 os.makedirs 而不是 tempfile.mkdtemp —— 后者建出来的目录在
    # Windows 沙箱下写入会被拒(实测 PermissionError: [Errno 13]), 原因不明,
    # 可能是其私有的权限位与沙箱的 ACL 规则不兼容。
    root_dir = _project_root()
    workdir = root_dir / f"_crack_{os.getpid()}_{int(time.time() * 1000) % 100000}"
    os.makedirs(workdir, exist_ok=True)
    worker_py = workdir / "_worker.py"
    worker_py.write_text(_WORKER_SRC, encoding="utf-8")
    root = str(root_dir)

    t0 = time.perf_counter()
    procs: list = []
    aborted = False
    try:
        for idx, (lo, hi) in enumerate(jobs):
            jobfile = workdir / f"job_{idx}.json"
            outfile = workdir / f"out_{idx}.json"
            jobfile.write_text(json.dumps({
                "start": lo, "stop": hi, "key_bits": key_bits,
                "pairs": [(int(p), int(c)) for p, c in pairs],
                "slice": slice_size, "out": str(outfile),
            }), encoding="utf-8")
            # 全部 stdio 走 DEVNULL: 沙箱禁止父进程通过管道取子进程输出
            proc = subprocess.Popen(
                [sys.executable, str(worker_py), root, str(jobfile)],
                cwd=root, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            procs.append({"proc": proc, "outfile": outfile, "share": hi - lo})

        # 轮询所有 out 文件求和; 每 interval 秒回调一次 progress
        # 注意 last 是**相对起点**的秒数(0.0), 不能写成 t0 —— t0 是绝对时钟,
        # 拿它跟 elapsed 相减永远是负数, 回调就一次都不会触发。
        last = 0.0
        last_tried = 0
        while True:
            tried = 0
            for item in procs:
                try:
                    data = json.loads(item["outfile"].read_text(encoding="utf-8"))
                except (OSError, ValueError):     # 还没写出第一版 / 正在被替换
                    continue
                tried += int(data.get("tried", 0))
            elapsed = time.perf_counter() - t0
            rate = tried / elapsed if elapsed else 0.0
            running = any(it["proc"].poll() is None for it in procs)
            # 有实际进展才回调(否则第一拍会打印 tried=0 的无意义进度),
            # 但收尾那一拍无论有没有新进展都要报一次最终值。
            if progress is not None and (not running
                                         or (elapsed - last >= interval
                                             and tried > last_tried)):
                last = elapsed
                last_tried = tried
                progress(tried, total, elapsed, rate,
                         (total - tried) / rate if rate else None)
            if not running:
                break
            if max_seconds is not None and elapsed >= max_seconds:
                aborted = True
                break
            time.sleep(0.05)
    except Exception as exc:                      # 起不了子进程 -> 回退单线程
        _kill_all(procs)
        shutil.rmtree(workdir, ignore_errors=True)
        fallback = crack(pairs, key_bits, interval=interval, progress=progress,
                         max_seconds=max_seconds)
        fallback["workers"] = 1
        fallback["parallel"] = "single"
        fallback["fallback_reason"] = f"{type(exc).__name__}: {exc}"
        return fallback
    if aborted:
        _kill_all(procs)

    # 收尾: 先读最终结果(每个 worker 收工时写了完整版本), 再删临时目录
    found: list[int] = []
    tried = 0
    for item in procs:
        try:
            data = json.loads(item["outfile"].read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        found.extend(int(k) for k in data.get("keys", []))
        tried += min(int(data.get("tried", 0)), item["share"])
    shutil.rmtree(workdir, ignore_errors=True)
    elapsed = time.perf_counter() - t0
    return {
        "keys": sorted(set(found)),
        "key_bits": key_bits,
        "stages": subkey_count(key_bits),
        "tried": tried,
        "span": total,
        "total": total,
        "elapsed": elapsed,
        "rate": tried / elapsed if elapsed else 0.0,
        "aborted": aborted,
        "workers": len(procs),
        "parallel": "subprocess",
    }


def _kill_all(procs) -> None:
    """杀掉还在跑的子进程, 等它们退出以免留下僵尸。"""
    for item in procs:
        proc = item["proc"]
        if proc.poll() is None:
            proc.kill()
    for item in procs:
        try:
            item["proc"].wait(timeout=5)
        except Exception:
            pass


# --------------------------------------------------------------------------
# 标定表
# --------------------------------------------------------------------------
def print_table(rate_per_stage: float | None = None) -> None:
    """打印各密钥长度的预计单线程耗时, 便于挑选合适的 ``--bits``。"""
    if rate_per_stage is None:
        rate_per_stage = measure_rate(MIN_KEY_BITS)
    print("=" * 78)
    print("扩展密钥空间 · 单线程暴力破解耗时标定表")
    print("=" * 78)
    print(f"测速基准: 单层(10-bit) 约 {format_int(rate_per_stage)} 候选密钥/秒")
    print(f"机器: {sys.platform}  Python {sys.version.split()[0]}")
    print("-" * 78)
    print(f"{'密钥长度':<10}{'级联层数':<10}{'密钥空间':<20}{'预计耗时':<20}{'适合演示'}")
    print("-" * 78)
    for L in range(MIN_KEY_BITS, 41):
        sec = estimate_seconds(L, rate_per_stage)
        if sec < 3:
            note = "瞬时(保底演示)"
        elif sec < 30:
            note = "短视频"
        elif sec < 300:
            note = "★ 推荐录视频"
        elif sec < 3600:
            note = "长视频"
        else:
            note = "太久(不建议)"
        print(f"{L} bit{'':<5}{subkey_count(L):<10}{format_int(1 << L):<20}"
              f"{format_duration(sec):<20}{note}")
    print("=" * 78)


# --------------------------------------------------------------------------
# 命令行
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="第 4 关(进阶): 扩展密钥空间下的暴力破解, 带时间戳与进度")
    parser.add_argument("--bits", type=int, default=DEFAULT_KEY_BITS,
                        help=f"主密钥长度 {MIN_KEY_BITS}~{MAX_KEY_BITS} "
                             f"(默认 {DEFAULT_KEY_BITS})")
    parser.add_argument("--pairs", type=int, default=None,
                        help="明文-密文对数量(默认自动: 足够唯一确定密钥)")
    parser.add_argument("--workers", type=int, default=1,
                        help="并行工作进程数(>1 时起子进程真并行; "
                             "纯 Python 多线程受 GIL 限制不会提速)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="进度刷新间隔秒数(默认 2.0)")
    parser.add_argument("--max-seconds", type=float, default=None,
                        help="超过该秒数就中止(防止密钥长度填太大)")
    parser.add_argument("--seed", type=int, default=None,
                        help="随机种子(给定则挑战与密钥可复现)")
    parser.add_argument("--key", default=None,
                        help="直接指定真实密钥(0/1 字符串), 默认随机生成")
    parser.add_argument("--table", action="store_true",
                        help="打印耗时标定表后退出")
    parser.add_argument("--for-seconds", type=float, default=None,
                        help="让程序推荐一个能跑约这么多秒的 --bits, 然后退出")
    args = parser.parse_args(argv)

    if args.table:
        print_table()
        return 0

    if args.for_seconds is not None:
        rate = measure_rate(MIN_KEY_BITS)
        best_bits, sec = suggest_bits(args.for_seconds, rate)
        print(f"想让破解耗时接近 {format_duration(args.for_seconds)}:")
        print(f"  推荐 --bits {best_bits}  (预计 {format_duration(sec)})")
        print(f"  命令: python -m sdes.longkey --bits {best_bits}")
        return 0

    key_bits = args.bits
    try:
        _check_key_bits(key_bits)
    except (ValueError, TypeError) as exc:
        print(f"[!] {exc}")
        return 2

    rng = random.Random(args.seed) if args.seed is not None else random.Random()
    if args.key:
        try:
            key_int, key_bits = bits_to_key(args.key)
        except ValueError as exc:
            print(f"[!] {exc}")
            return 2
        try:
            _check_key_bits(key_bits)
        except ValueError as exc:
            print(f"[!] {exc}")
            return 2
    else:
        key_int = random_key(key_bits, rng)

    n_pairs = args.pairs if args.pairs else default_pairs(key_bits)
    pairs = make_pairs(key_int, key_bits, n_pairs, rng)

    stages = subkey_count(key_bits)
    space = keyspace_size(key_bits)
    rate = measure_rate(key_bits, samples=8000)

    print("=" * 78)
    print("第 4 关(进阶) · 扩展密钥空间暴力破解")
    print("=" * 78)
    print(f"主密钥长度   : {key_bits} bit")
    print(f"级联层数     : {stages} 层 (每层标准 S-DES, 10-bit 子密钥)")
    print(f"密钥空间     : 2^{key_bits} = {format_int(space)} 个候选密钥"
          f"  (标准 S-DES 的 {space / 1024:,.0f} 倍)")
    print(f"明文-密文对  : {len(pairs)} 组")
    print(f"单线程速度   : 约 {format_int(rate)} 候选密钥/秒")
    print(f"预计耗时     : {format_duration(space / rate)}")
    print(f"并行方式     : {'多进程 ' + str(args.workers) + ' 个' if args.workers > 1 else '单线程'}")
    print("-" * 78)
    print(f"真实密钥     : {key_to_bits(key_int, key_bits)}")
    print("已知明文-密文对:")
    for i, (p, c) in enumerate(pairs, 1):
        print(f"  [{i}] 明文 {int_to_bits(p, BLOCK_BITS)}  ->  "
              f"密文 {int_to_bits(c, BLOCK_BITS)}")
    print("-" * 78)
    print(f"开始时间戳   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"开始破解 ... (每 {args.interval:g} 秒输出一次进度)")
    print("-" * 78, flush=True)

    def on_progress(tried, span, elapsed, rate_now, remaining):
        pct = 100.0 * tried / span if span else 0.0
        print(f"[{_ts()}] 已试 {format_int(tried)} / {format_int(span)} "
              f"({pct:5.1f}%)  {format_int(rate_now)} 键/秒  "
              f"已用 {format_duration(elapsed)}  "
              f"剩余 {format_duration(remaining)}", flush=True)

    if args.workers > 1:
        result = crack_subprocess(pairs, key_bits, workers=args.workers,
                                  interval=args.interval, progress=on_progress,
                                  max_seconds=args.max_seconds)
    else:
        result = crack(pairs, key_bits, interval=args.interval,
                       progress=on_progress, max_seconds=args.max_seconds)

    print("-" * 78)
    found = result["keys"]
    hit = key_int in found
    print(f"结束时间戳   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"实际耗时     : {format_duration(result['elapsed'])}")
    print(f"实测速度     : {format_int(result['rate'])} 候选密钥/秒")
    print(f"遍历条数     : {format_int(result['tried'])} / {format_int(result['span'])}")
    if result.get("fallback_reason"):
        print(f"注意         : 多进程不可用, 已回退单线程 ({result['fallback_reason']})")
    print(f"命中真实密钥 : {hit}")
    if found:
        shown = [key_to_bits(k, key_bits) for k in found[:10]]
        more = f"  ... 共 {len(found)} 个" if len(found) > 10 else ""
        print(f"候选密钥     : {shown}{more}")
        if len(found) == 1:
            print("             -> 唯一确定密钥 ✓")
        else:
            print(f"             -> 有 {len(found)} 个候选, 增加 --pairs 可进一步收窄")
    else:
        print("候选密钥     : 无 (未找到任何能解释全部明密文对的密钥)")
    print("=" * 78)
    if result.get("aborted"):
        print("[i] 已按 --max-seconds 中止; 想跑完请加大该值或减小 --bits")
    return 0 if hit else 1


if __name__ == "__main__":
    raise SystemExit(main())
