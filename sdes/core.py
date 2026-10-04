"""S-DES 位级核心算法。

本模块把作业规格中的算法描述逐条翻译成代码:

    2.3.1 加密:  C = IP^-1( f_K2( SW( f_K1( IP(P) ) ) ) )
    2.3.2 解密:  P = IP^-1( f_K1( SW( f_K2( IP(C) ) ) ) )
    2.3.3 密钥扩展: K_i = P8( Shift^i( P10(K) ) ),  i = 1, 2

其中 f_K(L, R) = ( L xor F(R, K), R ),  SW 为左右 4 位互换。
轮函数 F(R, K) = SPBox( SBox1(左4) || SBox2(右4) ), 输入为 EPBox(R) xor K。

内部实现使用整数位运算(见 *_int 函数), 对外提供 0/1 字符串接口。
两套接口结果完全一致, 由 tests/ 中的交叉验证保证。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 2.4 转换装置设定 (全部来自作业第 1 页)
# ---------------------------------------------------------------------------

#: 密钥扩展置换 P10, 10 -> 10 位
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)

#: 密钥压缩置换 P8, 10 -> 8 位
P8 = (6, 3, 7, 4, 8, 5, 10, 9)

#: 初始置换盒 IP, 8 -> 8 位
IP = (2, 6, 3, 1, 4, 8, 5, 7)

#: 最终置换盒 IP^-1, 8 -> 8 位
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

#: 扩展置换 EPBox, 4 -> 8 位
EP = (4, 1, 2, 3, 2, 3, 4, 1)

#: S 盒输出置换 SPBox (即 P4), 4 -> 4 位
SPBOX = (2, 4, 3, 1)

#: S 盒 1 —— 与标准 S-DES 的 S0 一致
#: 行 = 输入的第 1、4 位, 列 = 输入的第 2、3 位
SBOX1 = ((1, 0, 3, 2),
         (3, 2, 1, 0),
         (0, 2, 1, 3),
         (3, 1, 0, 2))

#: S 盒 2 —— **与标准 S-DES 的 S1 不同**, 以作业为准
#: 作业备注: "此处的 S-box2 与 PPT 上面的相比略有改动, 以此处为准。"
SBOX2 = ((0, 1, 2, 3),
         (2, 3, 1, 0),
         (3, 0, 1, 2),
         (2, 1, 0, 3))

#: 密钥左移调度: Shift^1 左移 1 位, Shift^2 左移 2 位
SHIFT_1 = 1
SHIFT_2 = 2

#: 分组长度 / 密钥长度 (bit)
BLOCK_BITS = 8
KEY_BITS = 10

_KEYS = 1 << KEY_BITS          # 1024
_BLOCKS = 1 << BLOCK_BITS      # 256


# ---------------------------------------------------------------------------
# 位串 <-> 整数
# ---------------------------------------------------------------------------

def bits_to_int(bits: str) -> int:
    """'1011' -> 11。仅接受 0/1 字符。"""
    bits = bits.strip()
    if not bits or any(c not in "01" for c in bits):
        raise ValueError(f"非法二进制串: {bits!r}")
    return int(bits, 2)


def int_to_bits(value: int, width: int) -> str:
    """11, 4 -> '1011' (左侧补零到 width 位)。"""
    if value < 0 or value >= (1 << width):
        raise ValueError(f"数值 {value} 超出 {width} bit 范围")
    return format(value, f"0{width}b")


def validate_key(key: str) -> int:
    """校验 10-bit 密钥字符串并返回整数表示。"""
    key = key.strip().replace(" ", "")
    if len(key) != KEY_BITS:
        raise ValueError(f"密钥必须为 {KEY_BITS} bit, 当前 {len(key)} bit")
    return bits_to_int(key)


def validate_block(block: str) -> int:
    """校验 8-bit 数据字符串并返回整数表示。"""
    block = block.strip().replace(" ", "")
    if len(block) != BLOCK_BITS:
        raise ValueError(f"数据必须为 {BLOCK_BITS} bit, 当前 {len(block)} bit")
    return bits_to_int(block)


# ---------------------------------------------------------------------------
# 基本位运算
# ---------------------------------------------------------------------------

def _permute(value: int, n: int, table: tuple) -> int:
    """按 1-indexed 置换表重排 n 位整数(MSB 为位置 1)。

    输出第 i 位 = 输入的 table[i] 位。
    """
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (n - pos)) & 1)
    return out


def _rot_left(value: int, n: int, k: int) -> int:
    """n 位整数循环左移 k 位。"""
    k %= n
    mask = (1 << n) - 1
    return ((value << k) | (value >> (n - k))) & mask


def _sbox(box: tuple, nibble: int) -> int:
    """4-bit 输入查 S 盒, 返回 2-bit 输出。

    行号 = 第 1、4 位; 列号 = 第 2、3 位。
    """
    b1 = (nibble >> 3) & 1
    b2 = (nibble >> 2) & 1
    b3 = (nibble >> 1) & 1
    b4 = nibble & 1
    row = (b1 << 1) | b4
    col = (b2 << 1) | b3
    return box[row][col]


def _f(block: int, subkey: int) -> int:
    """轮函数 F: 4-bit R 与 8-bit 子密钥 -> 4-bit 输出。"""
    expanded = _permute(block, 4, EP) ^ subkey      # EPBox(R) xor K
    left = _sbox(SBOX1, (expanded >> 4) & 0xF)
    right = _sbox(SBOX2, expanded & 0xF)
    return _permute((left << 2) | right, 4, SPBOX)


def _fk(block: int, subkey: int) -> int:
    """f_K(L, R) = ( L xor F(R, K), R )。"""
    left = (block >> 4) & 0xF
    right = block & 0xF
    return (((left ^ _f(right, subkey)) << 4) | right) & 0xFF


def _swap(block: int) -> int:
    """SW: 左右 4 位互换。"""
    return ((block & 0xF) << 4) | ((block >> 4) & 0xF)


# ---------------------------------------------------------------------------
# 2.3.3 密钥扩展
# ---------------------------------------------------------------------------

def key_schedule(key) -> tuple:
    """由 10-bit 主密钥生成 (K1, K2)。

    K1 = P8( Shift^1( P10(K) ) )
    K2 = P8( Shift^2( Shift^1( P10(K) ) ) )

    参数 key 可以是 '0'/'1' 字符串或整数。
    """
    k = validate_key(key) if isinstance(key, str) else key
    permuted = _permute(k, KEY_BITS, P10)
    left = (permuted >> 5) & 0x1F
    right = permuted & 0x1F

    left1 = _rot_left(left, 5, SHIFT_1)
    right1 = _rot_left(right, 5, SHIFT_1)
    k1 = _permute((left1 << 5) | right1, KEY_BITS, P8)

    left2 = _rot_left(left1, 5, SHIFT_2)
    right2 = _rot_left(right1, 5, SHIFT_2)
    k2 = _permute((left2 << 5) | right2, KEY_BITS, P8)

    return k1, k2


# ---------------------------------------------------------------------------
# 2.3.1 / 2.3.2 加解密 (整数接口)
# ---------------------------------------------------------------------------

def encrypt_int(plaintext: int, key: int) -> int:
    """8-bit 明文 + 10-bit 密钥 -> 8-bit 密文。"""
    k1, k2 = key_schedule(key)
    state = _permute(plaintext, BLOCK_BITS, IP)
    state = _fk(state, k1)
    state = _swap(state)
    state = _fk(state, k2)
    return _permute(state, BLOCK_BITS, IP_INV)


def decrypt_int(ciphertext: int, key: int) -> int:
    """8-bit 密文 + 10-bit 密钥 -> 8-bit 明文(子密钥顺序反转)。"""
    k1, k2 = key_schedule(key)
    state = _permute(ciphertext, BLOCK_BITS, IP)
    state = _fk(state, k2)
    state = _swap(state)
    state = _fk(state, k1)
    return _permute(state, BLOCK_BITS, IP_INV)


# ---------------------------------------------------------------------------
# 对外字符串接口
# ---------------------------------------------------------------------------

def encrypt(plaintext: str, key: str) -> str:
    """加密一个 8-bit 分组, 参数与返回值为 '0'/'1' 字符串。"""
    return int_to_bits(encrypt_int(validate_block(plaintext), validate_key(key)),
                       BLOCK_BITS)


def decrypt(ciphertext: str, key: str) -> str:
    """解密一个 8-bit 分组, 参数与返回值为 '0'/'1' 字符串。"""
    return int_to_bits(decrypt_int(validate_block(ciphertext), validate_key(key)),
                       BLOCK_BITS)


def encrypt_hex(plaintext_hex: str, key_bits: str) -> str:
    """便捷接口: 2 位 hex 明文 -> hex 密文(供 GUI / CLI 使用)。"""
    return format(encrypt_int(int(plaintext_hex, 16), validate_key(key_bits)), "02X")


def decrypt_hex(ciphertext_hex: str, key_bits: str) -> str:
    """便捷接口: 2 位 hex 密文 -> hex 明文。"""
    return format(decrypt_int(int(ciphertext_hex, 16), validate_key(key_bits)), "02X")


# ---------------------------------------------------------------------------
# 调试辅助
# ---------------------------------------------------------------------------

def trace(plaintext: str, key: str) -> dict:
    """返回一次加密的中间状态, 便于与手算结果比对(第 1 关调试用)。"""
    k = validate_key(key)
    p = validate_block(plaintext)
    k1, k2 = key_schedule(k)
    permuted = _permute(k, KEY_BITS, P10)

    steps = {"key": int_to_bits(k, 10), "plaintext": int_to_bits(p, 8)}
    steps["P10(K)"] = int_to_bits(permuted, 10)
    steps["L1|R1 (P10 左5|右5)"] = (
        int_to_bits((permuted >> 5) & 0x1F, 5) + "|" + int_to_bits(permuted & 0x1F, 5))
    steps["K1"] = int_to_bits(k1, 8)
    steps["K2"] = int_to_bits(k2, 8)

    ip = _permute(p, 8, IP)
    steps["IP(P)"] = int_to_bits(ip, 8)
    steps["L0"] = int_to_bits((ip >> 4) & 0xF, 4)
    steps["R0"] = int_to_bits(ip & 0xF, 4)
    steps["F(R0,K1)"] = int_to_bits(_f(ip & 0xF, k1), 4)
    after_fk1 = _fk(ip, k1)
    steps["f_K1(IP(P))"] = int_to_bits(after_fk1, 8)
    swapped = _swap(after_fk1)
    steps["SW(...)"] = int_to_bits(swapped, 8)
    steps["F(L1',K2)"] = int_to_bits(_f(swapped & 0xF, k2), 4)
    after_fk2 = _fk(swapped, k2)
    steps["f_K2(SW(...))"] = int_to_bits(after_fk2, 8)
    steps["IP^-1(...) = C"] = int_to_bits(_permute(after_fk2, 8, IP_INV), 8)
    return steps


if __name__ == "__main__":  # 简易自检
    import sys
    pt, key = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ("00000000", "0000011111")
    ct = encrypt(pt, key)
    print(f"密钥 = {key}\n明文 = {pt}\n密文 = {ct}\n还原 = {decrypt(ct, key)}")
    print(f"K1/K2 = {[int_to_bits(x, 8) for x in key_schedule(key)]}")
