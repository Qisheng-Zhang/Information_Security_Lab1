"""编解码层: 字符串 / 字节 <-> bit 串。

覆盖第 3 关(扩展功能)的需求:
- ASCII (UTF-8) 字符串按 1 Byte 分组加密
- bit 串与 hex 互转, 方便 GUI 显示
- 任意长度字节流的分组 / 合并(不足整字节的尾巴单独处理)
"""

from __future__ import annotations

from .core import BLOCK_BITS, decrypt_int, encrypt_int

#: 加密模式
MODE_PAD = "pad"      # 最后一组不足 8 bit 时补零(简单, 需知道原长)
MODE_RAW = "raw"      # 不足 8 bit 的尾巴不做加密, 原样输出(仅用于演示)


def bytes_to_bits(data: bytes) -> str:
    """b'AB' -> '0100000101000010'。"""
    return "".join(format(b, "08b") for b in data)


def bits_to_bytes(bits: str) -> bytes:
    """'0100000101000010' -> b'AB'。长度不是 8 的倍数时抛错。"""
    bits = bits.strip().replace(" ", "")
    if len(bits) % 8:
        raise ValueError(f"bit 串长度 {len(bits)} 不是 8 的倍数")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def text_to_bits(text: str, encoding: str = "utf-8") -> str:
    """字符串 -> bit 串(按指定编码转字节后再展开)。"""
    return bytes_to_bits(text.encode(encoding))


def bits_to_text(bits: str, encoding: str = "utf-8", errors: str = "strict") -> str:
    """bit 串 -> 字符串。"""
    return bits_to_bytes(bits).decode(encoding, errors=errors)


def split_blocks(bits: str, size: int = BLOCK_BITS) -> list:
    """把 bit 串切成固定长度的分组, 最后一组可能短于 size。"""
    bits = bits.strip().replace(" ", "")
    blocks = [bits[i:i + size] for i in range(0, len(bits), size)]
    return [b for b in blocks if b]


def join_blocks(blocks) -> str:
    """分组列表拼回一个 bit 串。"""
    return "".join(blocks)


def hex_to_bits(hexstr: str, width: int = 0) -> str:
    """'A5' -> '10100101'。width 用于补齐位宽(0 表示自动)。"""
    h = hexstr.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    if not h:
        return "0" * width if width else ""
    value = int(h, 16)
    width = width or max(len(h) * 4, value.bit_length())
    return format(value, f"0{width}b")


def bits_to_hex(bits: str) -> str:
    """'10100101' -> 'A5'。"""
    bits = bits.strip().replace(" ", "")
    pad = (-len(bits)) % 4
    bits = "0" * pad + bits
    return format(int(bits, 2), f"0{len(bits) // 4}X")


# ---------------------------------------------------------------------------
# 字符串加解密 (第 3 关核心)
# ---------------------------------------------------------------------------

def encrypt_bytes(data: bytes, key: str) -> bytes:
    """按字节分组加密整个字节流。"""
    k = int(key, 2) if isinstance(key, str) else key
    return bytes(encrypt_int(b, k) for b in data)


def decrypt_bytes(data: bytes, key: str) -> bytes:
    """按字节分组解密整个字节流。"""
    k = int(key, 2) if isinstance(key, str) else key
    return bytes(decrypt_int(b, k) for b in data)


def encrypt_text(text: str, key: str, encoding: str = "utf-8") -> str:
    """明文字符串 -> 密文 bit 串。"""
    return bytes_to_bits(encrypt_bytes(text.encode(encoding), key))


def decrypt_text(bits: str, key: str, encoding: str = "utf-8",
                 errors: str = "strict") -> str:
    """密文 bit 串 -> 明文字符串。"""
    return decrypt_bytes(bits_to_bytes(bits), key).decode(encoding, errors=errors)


def encrypt_text_hex(text: str, key: str, encoding: str = "utf-8") -> str:
    """明文字符串 -> 压缩的 hex 密文(误码率演示时更易读)。"""
    return bits_to_hex(encrypt_text(text, key, encoding))


def decrypt_hex_text(hexstr: str, key: str, encoding: str = "utf-8",
                     errors: str = "strict") -> str:
    """hex 密文 -> 明文字符串。"""
    return decrypt_text(hex_to_bits(hexstr), key, encoding, errors)


def encrypt_bits_partial(bits: str, key: str, mode: str = MODE_PAD) -> str:
    """加密任意长度 bit 串(不要求 8 的倍数)。

    mode=MODE_PAD: 末组右侧补 0 到 8 bit 后加密, 结果仍为补齐后的长度。
    mode=MODE_RAW: 末组不足 8 bit 则原样保留(不加密)。
    """
    blocks = split_blocks(bits, BLOCK_BITS)
    k = int(key, 2) if isinstance(key, str) else key
    out = []
    for blk in blocks:
        if len(blk) == BLOCK_BITS:
            out.append(format(encrypt_int(int(blk, 2), k), "08b"))
        elif mode == MODE_PAD:
            out.append(format(encrypt_int(int(blk.ljust(BLOCK_BITS, "0"), 2), k), "08b"))
        else:
            out.append(blk)
    return "".join(out)
