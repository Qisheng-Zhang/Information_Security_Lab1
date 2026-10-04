# -*- coding: utf-8 -*-
"""第 2 关 · 交叉测试：与本项目之外的"对方程序"互验。

作业文档 3.2 规定的是**两种**交叉测试方式::

    设有A和B两组位同学(选择相同的密钥); 则
    方式①  A、B组同学编写的程序对明文 P 进行加密得到相同的密文 C;
    方式②  B组同学接收到 A组程序加密的密文 C, 使用 B组程序进行解密
           可得到与 A 相同的 P。

本脚本把"对方的程序"当作一个**外部实现**加载进来（独立命名空间，不会
碰到本项目的 ``sdes`` 包），双方各自计算、逐条比对：屏幕输出便于截图，
同时可写一份 Markdown 便于贴进测试报告。

用法::

    python -m tests.cross_test                      # 默认对手: _组2参考/SDES/sdes
    python -m tests.cross_test --other <目录> --name 第三组
    python -m tests.cross_test --full               # 全空间 1024x256 穷举
    python -m tests.cross_test --md docs/交叉测试_第二组.md

注意: 对方的实现必须是"另一套代码"。若两次都用本项目的 ``sdes.core``，
只能证明程序可复现，不能证明算法实现正确。
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import sys
import time
import types
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sdes import core as ours  # noqa: E402

#: 默认对手目录：本项目根目录下的第二组参考实现
DEFAULT_OTHER = _ROOT / "_组2参考" / "SDES" / "sdes"
DEFAULT_LABEL = "第二组"

#: 第二组 tests/run_all.py level2() 采用的 5 条标准向量 (密钥, 明文)
STANDARD_VECTORS = [
    (0b1010000010, 0b01110010),
    (0b0111111101, 0b01010101),
    (0b1111111111, 0b11111111),
    (0b0000000000, 0b00000000),
    (0b0010010111, 0b10100101),
]

#: 需要双向比对的转换单元；(我方属性名, 对方可能的属性名)
_TABLE_ALIASES = [
    ("P10", ("P10",)),
    ("P8", ("P8",)),
    ("IP", ("IP",)),
    ("IP_INV", ("IP_INV", "IP_INVERSE", "IP_INVERS")),
    ("EP", ("EP", "EPBOX", "EP_BOX")),
    ("SPBOX", ("SPBOX", "P4", "SP_BOX", "SPBOX4")),
    ("SBOX1", ("SBOX1", "S_BOX_1", "SBOX_1")),
    ("SBOX2", ("SBOX2", "S_BOX_2", "SBOX_2")),
]

_LINE = "=" * 78
_THIN = "-" * 78


def _find_attr(module, names):
    """在模块里按候选名字依次查找属性。"""
    for name in names:
        if hasattr(module, name):
            return getattr(module, name)
    return None


def load_external(path: Path, label: str):
    """把对方的实现加载成独立包，返回 (包对象, 已加载模块名列表)。"""
    path = Path(path).resolve()
    if not path.is_dir():
        raise SystemExit(f"[!] 找不到对方的实现目录: {path}")
    pkg_name = "external_sdes"
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = [str(path)]
    pkg.__package__ = pkg_name
    sys.modules[pkg_name] = pkg
    loaded = []
    for py in sorted(path.glob("*.py")):
        if py.name == "__init__.py":
            continue
        mod_name = f"{pkg_name}.{py.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, str(py))
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:                      # 对方代码可能有导入失败
            print(f"  (跳过 {py.name}: {exc})")
            continue
        setattr(pkg, py.stem, mod)
        loaded.append(py.stem)
    if not loaded:
        raise SystemExit(f"[!] {label} 的实现里没有可加载的模块: {path}")
    return pkg, loaded


class ExternalAdapter:
    """把对方实现的不同接口风格，统一成 encrypt/decrypt/subkeys。"""

    def __init__(self, pkg, label: str):
        self.label = label
        self.pkg = pkg
        self.core = getattr(pkg, "core", None)
        if self.core is None:
            raise SystemExit(f"[!] {label} 的实现里没有 core 模块")
        self.tables_mod = getattr(pkg, "tables", self.core)
        if not hasattr(self.core, "encrypt_byte") and not hasattr(
                self.core, "encrypt_block"):
            raise SystemExit(f"[!] {label} 的 core 里找不到加密函数")
        self._to_bits = _find_attr(self.core, ("int_to_bits",))
        self._to_int = _find_attr(self.core, ("bits_to_int",))

    # -- 加解密 ---------------------------------------------------------
    def encrypt(self, plain: int, key: int) -> int:
        if hasattr(self.core, "encrypt_byte"):
            return self.core.encrypt_byte(plain, key)
        bits = self.core.encrypt_block(self._to_bits(plain, 8),
                                       self._to_bits(key, 10))
        return self._to_int(bits)

    def decrypt(self, cipher: int, key: int) -> int:
        if hasattr(self.core, "decrypt_byte"):
            return self.core.decrypt_byte(cipher, key)
        bits = self.core.decrypt_block(self._to_bits(cipher, 8),
                                       self._to_bits(key, 10))
        return self._to_int(bits)

    # -- 密钥扩展 -------------------------------------------------------
    def subkeys(self, key: int):
        gen = _find_attr(self.core, ("generate_subkeys", "key_schedule",
                                     "subkeys"))
        if gen is None:
            return None
        try:
            return gen(self._to_bits(key, 10))          # 对方多收 bit 列表
        except Exception:
            pass
        try:
            return gen(key)                             # 也许收整数
        except Exception:
            return None

    def subkeys_as_int(self, key: int):
        pair = self.subkeys(key)
        if pair is None:
            return None
        k1, k2 = pair
        try:
            return (self._to_int(k1), self._to_int(k2))
        except Exception:
            return (int(k1), int(k2))

    # -- 转换单元 -------------------------------------------------------
    def tables(self) -> dict:
        found = {}
        for attr, aliases in _TABLE_ALIASES:
            value = _find_attr(self.tables_mod, aliases)
            if value is None and self.tables_mod is not self.core:
                value = _find_attr(self.core, aliases)
            found[attr] = value
        return found

    # -- 第 3 关字符串（可选） -------------------------------------------
    def text_module(self):
        return getattr(self.pkg, "text_mode", None)


def collect_vectors(full: bool, extra: int, seed: int):
    """返回 [(明文, 密钥, 来源说明), ...]。

    ``--full`` 时全空间本身就包含那 5 条标准向量，故不再单独前置，避免重复。
    """
    rows = []
    if full:
        for key in range(1 << 10):
            for plain in range(1 << 8):
                rows.append((plain, key, "全空间"))
        return rows
    for key, plain in STANDARD_VECTORS:
        rows.append((plain, key, "标准向量"))
    if extra > 0:
        rng = random.Random(seed)
        for _ in range(extra):
            plain = rng.randrange(1 << 8)
            key = rng.randrange(1 << 10)
            rows.append((plain, key, "随机抽样"))
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="第 2 关交叉测试: 与本项目之外的对方程序互验")
    parser.add_argument("--other", default=str(DEFAULT_OTHER),
                        help="对方实现的 sdes 包目录")
    parser.add_argument("--name", default=DEFAULT_LABEL, help="对方的称呼")
    parser.add_argument("--full", action="store_true",
                        help="全空间穷举 1024 密钥 x 256 明文 (较慢)")
    parser.add_argument("-n", "--extra", type=int, default=200,
                        help="随机抽样条数 (默认 200, --full 时忽略)")
    parser.add_argument("--seed", type=int, default=20261008, help="抽样随机种子")
    parser.add_argument("--md", default=None, help="同时写入 Markdown 文件")
    args = parser.parse_args(argv)

    lines = []

    def out(text=""):
        print(text)
        lines.append(text)

    other_pkg, loaded = load_external(Path(args.other), args.name)
    other = ExternalAdapter(other_pkg, args.name)

    out(_LINE)
    out(f"第 2 关 · 交叉测试   ——   我方程序  vs  {args.name}")
    out(_LINE)
    out(f"我方实现 : sdes/core.py  (整数位运算)")
    out(f"对方实现 : {Path(args.other).resolve()}")
    out(f"对方模块 : {', '.join(loaded)}")
    out(_LINE)
    out()

    # ---- 1. 转换单元是否一致 -----------------------------------------
    out("[1] 转换单元 (P-Box / S-Box) 逐项比对")
    out(_THIN)
    their_tables = other.tables()
    spec_ok = True
    for attr, _aliases in _TABLE_ALIASES:
        mine = getattr(ours, attr)
        theirs = their_tables.get(attr)
        if theirs is None:
            out(f"   {attr:<8} 对方未提供同名常量")
            spec_ok = False
            continue
        same = tuple(theirs) == tuple(mine)
        spec_ok &= same
        out(f"   {attr:<8} {'一致 ✓' if same else '不一致 ✗'}")
    out(f"   -> 转换单元{'完全一致，双方口径相同' if spec_ok else '存在差异'}")
    out()

    # ---- 2. 密钥扩展 --------------------------------------------------
    out("[2] 密钥扩展: 全部 1024 个主密钥的 (K1, K2)")
    out(_THIN)
    subkey_bad = []
    if other.subkeys(0) is None:
        out("   对方未提供 generate_subkeys/key_schedule，跳过")
        subkey_ok = True
    else:
        for key in range(1 << 10):
            mine = ours.key_schedule(key)
            theirs = other.subkeys_as_int(key)
            if mine != theirs:
                subkey_bad.append(key)
        out(f"   比对 {1 << 10} 个主密钥 -> 不一致 {len(subkey_bad)} 个")
        out(f"   -> {'全部一致 ✓' if not subkey_bad else f'差异: {subkey_bad[:5]}'}")
        subkey_ok = not subkey_bad
    out(f"   教材样例 K=1010000010 -> 我方 K1={ours.key_schedule(0b1010000010)[0]:08b}"
        f" K2={ours.key_schedule(0b1010000010)[1]:08b} (教材 10100100 / 01000011)")
    out()

    # ---- 3. 方式① 加密一致 -------------------------------------------
    vectors = collect_vectors(args.full, args.extra, args.seed)
    out(f"[3] 方式①  加密一致: 同一 (明文, 密钥) 双方各自加密")
    out(_THIN)
    if args.full:
        out("   模式: 全空间穷举 1024 密钥 x 256 明文")
    else:
        out(f"   模式: {len(STANDARD_VECTORS)} 条标准向量 + {args.extra} 条随机抽样")
    out()
    out(f"   {'#':<5}{'密钥 K':<12}{'明文 P':<11}{'我方密文':<11}"
        f"{'对方密文':<11}{'一致':<6}")
    out("   " + "-" * 70)
    mismatch1 = []
    t0 = time.perf_counter()
    # 展示用: 先列 5 条标准向量 (便于与对方报告逐行对照)，再补随机/全空间前几条
    display = [(plain, key, "标准向量") for key, plain in STANDARD_VECTORS]
    standard_set = {(plain, key) for key, plain in STANDARD_VECTORS}
    for row in vectors:
        if (row[0], row[1]) not in standard_set:
            display.append(row)
        if len(display) >= 12:
            break
    display_set = {(p, k) for p, k, _ in display}
    for idx, (plain, key, _src) in enumerate(display, 1):
        c_mine = ours.encrypt_int(plain, key)
        c_theirs = other.encrypt(plain, key)
        if c_mine != c_theirs:
            mismatch1.append((plain, key, c_mine, c_theirs))
        out(f"   {idx:<5}{key:010b}  {plain:08b}   {c_mine:08b}   "
            f"{c_theirs:08b}   {'✓' if c_mine == c_theirs else '✗'}")
    for plain, key, _src in vectors:
        if (plain, key) in display_set:
            continue
        c_mine = ours.encrypt_int(plain, key)
        c_theirs = other.encrypt(plain, key)
        if c_mine != c_theirs:
            mismatch1.append((plain, key, c_mine, c_theirs))
    t1 = time.perf_counter()
    out(f"   ... 其余 {len(vectors) - len(display)} 条同理 (完整结果见下方统计)")
    out("   " + "-" * 70)
    out(f"   共比对 {len(vectors)} 组 -> 密文不一致 {len(mismatch1)} 组, "
        f"耗时 {t1 - t0:.2f} s")
    out(f"   -> {'全部一致 ✓ 方式① 通过' if not mismatch1 else '存在不一致 ✗'}")
    out()

    # ---- 4. 方式② 解密互操作（对方 -> 我方） --------------------------
    out("[4] 方式②  解密互操作: 对方程序加密出的密文, 我方程序解密")
    out(_THIN)
    fail2 = []
    t0 = time.perf_counter()
    for plain, key, _src in vectors:
        cipher = other.encrypt(plain, key)          # 对方的程序加密
        if ours.decrypt_int(cipher, key) != plain:  # 我方程序解密
            fail2.append((plain, key))
    t1 = time.perf_counter()
    out(f"   对方加密 {len(vectors)} 组密文 -> 我方解密还原失败 {len(fail2)} 组, "
        f"耗时 {t1 - t0:.2f} s")
    out(f"   -> {'全部还原成功 ✓ 方式② 通过' if not fail2 else '存在失败 ✗'}")
    out()

    # ---- 5. 方式② 反向（我方 -> 对方） --------------------------------
    out(f"[5] 方式② 反向: 我方程序加密出的密文, {args.name}程序解密")
    out(_THIN)
    fail3 = []
    t0 = time.perf_counter()
    for plain, key, _src in vectors:
        cipher = ours.encrypt_int(plain, key)       # 我方程序加密
        if other.decrypt(cipher, key) != plain:     # 对方程序解密
            fail3.append((plain, key))
    t1 = time.perf_counter()
    out(f"   我方加密 {len(vectors)} 组密文 -> 对方解密还原失败 {len(fail3)} 组, "
        f"耗时 {t1 - t0:.2f} s")
    out(f"   -> {'全部还原成功 ✓ 反向通过' if not fail3 else '存在失败 ✗'}")
    out()

    # ---- 6. 第 3 关字符串互验（若对方提供） ---------------------------
    text_mod = other.text_module()
    if text_mod is not None and hasattr(text_mod, "encrypt_text"):
        out("[6] 附加 · 第 3 关字符串互验 (ASCII, 逐字节)")
        out(_THIN)
        key = 0b1010000010
        samples = ["This is a test", "S-DES", "a", "Hello, CQU!"]
        text_bad = 0
        for msg in samples:
            mine_hex = " ".join(
                f"{ours.encrypt_int(b, key):02x}" for b in msg.encode("ascii"))
            try:
                theirs = text_mod.encrypt_text(msg, key)
                theirs_hex = " ".join(f"{b:02x}" for b in theirs)
            except Exception as exc:
                out(f"   {msg!r:<20} 对方调用失败: {exc}")
                text_bad += 1
                continue
            same = mine_hex == theirs_hex
            text_bad += 0 if same else 1
            out(f"   {msg!r:<20} {'一致 ✓' if same else '不一致 ✗'}   {mine_hex}")
        out(f"   -> {'字符串逐字节密文全部一致 ✓' if not text_bad else '存在差异 ✗'}")
        out()

    # ---- 总结 ---------------------------------------------------------
    ok = (spec_ok and subkey_ok and not mismatch1 and not fail2 and not fail3)
    out(_LINE)
    out("总结论")
    out(_THIN)
    out(f"   [1] 转换单元一致          {'✓ 通过' if spec_ok else '✗ 失败'}")
    out(f"   [2] 密钥扩展全空间一致    {'✓ 通过' if subkey_ok else '✗ 失败'}")
    out(f"   [3] 方式① 加密一致        {'✓ 通过' if not mismatch1 else '✗ 失败'}"
        f"   ({len(vectors)} 组)")
    out(f"   [4] 方式② 对方加密我方解  {'✓ 通过' if not fail2 else '✗ 失败'}"
        f"   ({len(vectors)} 组)")
    out(f"   [5] 方式② 我方加密对方解  {'✓ 通过' if not fail3 else '✗ 失败'}"
        f"   ({len(vectors)} 组)")
    out()
    out("   " + ("交叉测试全部通过 ✓  两套独立实现的算法口径完全一致。"
                if ok else "存在不一致 ✗  请检查双方的转换单元与密钥扩展步骤。"))
    out(_LINE)

    if args.md:
        md_path = Path(args.md)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        header = [
            f"# 第 2 关 · 交叉测试记录（我方 vs {args.name}）",
            "",
            f"- 我方实现：`sdes/core.py`（整数位运算）",
            f"- 对方实现：`{Path(args.other).resolve()}`",
            f"- 比对规模：{len(vectors)} 组 (明文, 密钥)",
            f"- 生成命令：`python -m tests.cross_test "
            f"{'--full' if args.full else f'-n {args.extra}'}`",
            "",
            "## 原始输出",
            "",
            "```text",
        ]
        md_path.write_text("\n".join(header + lines + ["```", ""]),
                           encoding="utf-8")
        print(f"\nMarkdown 结果已写入: {md_path}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
