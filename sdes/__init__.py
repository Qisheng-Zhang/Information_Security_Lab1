"""S-DES (Simplified DES) 算法实现 —— 信息安全导论 作业1.

本包按照《作业1：S-DES算法实现》给出的规格实现, 规格与标准 S-DES
(Schaefer, 1996) 一致, 唯一差别是 SBox2 被改写:

    SBox2 = [(0,1,2,3); (2,3,1,0); (3,0,1,2); (2,1,0,3)]

(标准 S-DES 的 S1 = [(0,1,2,3); (2,0,1,3); (3,0,1,0); (2,1,0,3)])

因此公开资料上的标准测试向量**不能**直接用作本作业的期望密文,
必须使用本实现自身的一致性(回环)与交叉测试来验证。

模块划分
--------
- core.py   : 位级核心算法(置换表、密钥调度、S 盒、加解密)
- codec.py  : ASCII/UTF-8 字符串 <-> bit 串、hex、字节分组编解码
- crack.py  : 暴力破解(含多线程)与密钥碰撞 / 封闭测试分析
- gui.py    : tkinter GUI, 按作业 5 个关卡分页
- server.py / client.py : 第 3 关的 TCP Socket 加密通信演示

位编号约定
----------
所有置换表使用 **1-indexed** 编号, 最左位为位置 1。
置换 P 的输出第 i 位 = 输入的 P[i] 位。
"""

import importlib

__version__ = "1.0.0"

# 子模块 -> 该模块对外暴露的符号。用于惰性重导出:
#   from sdes import encrypt        # 触发 _LAZY["core"] 的导入
#   from sdes import core           # 常规子模块导入, 不经过 __getattr__
#
# 之所以不写成 "from .core import ..." 的即时导入, 是因为包在导入时就把
# core/codec/crack 全部装载进 sys.modules, 之后再执行
# "python -m sdes.core" 之类的命令时, runpy 会报
#   RuntimeWarning: 'sdes.core' found in sys.modules after import of
#   package 'sdes', but prior to execution of 'sdes.core'
# 惰性导出既保留了 sdes.encrypt 这类写法, 又消除了该告警。
_LAZY = {
    "core": (
        "P10", "P8", "IP", "IP_INV", "EP", "SPBOX", "SBOX1", "SBOX2",
        "BLOCK_BITS", "KEY_BITS",
        "encrypt", "decrypt", "encrypt_int", "decrypt_int", "key_schedule",
        "bits_to_int", "int_to_bits", "validate_key", "validate_block",
        "trace", "encrypt_hex", "decrypt_hex",
    ),
    "codec": (
        "text_to_bits", "bits_to_text", "hex_to_bits", "bits_to_hex",
        "bytes_to_bits", "bits_to_bytes", "split_blocks", "join_blocks",
        "encrypt_bytes", "decrypt_bytes", "encrypt_text", "decrypt_text",
        "encrypt_text_hex", "decrypt_hex_text",
        "encrypt_bits_partial", "MODE_PAD", "MODE_RAW",
    ),
    "crack": (
        "brute_force", "brute_force_threaded", "brute_force_by_key",
        "analyze_collisions", "equivalent_key_classes", "collision_report",
    ),
}

# 反向索引: 符号名 -> 子模块名
_OWNER = {name: mod for mod, names in _LAZY.items() for name in names}

__all__ = sorted(set(_OWNER) | {"__version__"})


def __getattr__(name: str):
    """PEP 562 模块级惰性属性: 首次访问时才导入对应子模块。"""
    module_name = _OWNER.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value  # 缓存, 后续访问不再走 __getattr__
    return value


def __dir__():
    return sorted(set(globals()) | set(_OWNER))
