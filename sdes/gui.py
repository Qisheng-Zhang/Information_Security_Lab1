"""图形界面(GUI): 以 tkinter 实现的 S-DES 演示程序.

对应作业要求:
  第 1 关(基本测试)  "提供 GUI 加解密支持用户交互。输入可以是 8bit 的数据和 10bit 的密钥, 输出是 8bit 的密文。"
  第 2 关(交叉测试)  相同算法流程与转换单元, 保证跨平台一致; 提供规范化测试向量导出/比对。
  第 3 关(扩展功能)  ASCII 字符串(按 1 Byte 分组)加密, 并演示 TCP Socket 网络通信场景。
  第 4 关(暴力破解)  已知明文密文对, 多线程穷举密钥, 计时展示破解时长。
  第 5 关(封闭测试)  密钥碰撞分析: 是否存在多个密钥得到同一密文。

运行方式(在项目根目录下):
    python -m sdes.gui

说明: 无第三方依赖, 仅使用标准库 tkinter。耗时操作(暴力破解、全空间碰撞
枚举、TCP 通信)一律放在工作线程中执行, 避免主界面卡死。
"""

from __future__ import annotations

import json
import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import codec, core
from .crack import (_BLOCK_SPACE, _KEY_SPACE, analyze_collisions,
                    brute_force, brute_force_threaded, collision_report,
                    equivalent_key_classes)

APP_TITLE = "S-DES 算法演示平台 —— 信息安全导论 作业1"
DEFAULT_KEY = "1010000010"
DEFAULT_PT = "10010111"


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------
def _clean_bits(text: str) -> str:
    """去掉空白与下划线, 便于用户粘贴带空格的 bit 串。"""
    return "".join(ch for ch in text if ch not in " \t\r\n_")


class _Worker:
    """在后台线程里跑一段函数, 结束后用 after() 把结果丢回主线程。"""

    def __init__(self, widget: tk.Widget):
        self.widget = widget
        self.thread: threading.Thread | None = None

    @property
    def busy(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def run(self, func, on_done, on_error=None):
        if self.busy:
            return
        self.widget.configure(cursor="watch")

        def target():
            try:
                result = func()
            except Exception as exc:  # noqa: BLE001 - 需要把异常显示给用户
                self.widget.after(0, lambda: self._finish(on_error, exc))
            else:
                self.widget.after(0, lambda: self._finish(on_done, result))

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()

    def _finish(self, callback, payload):
        self.widget.configure(cursor="")
        if callback is not None:
            callback(payload)


def _scrolled_text(parent, height=14, width=88, **kw) -> tk.Text:
    """带垂直滚动条的只读 Text。"""
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True, **kw)
    text = tk.Text(frame, height=height, width=width, wrap="word",
                   font=("Consolas", 10), background="#fbfbfb")
    bar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=bar.set)
    text.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")
    return text


def _set_text(widget: tk.Text, content: str):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    widget.configure(state="disabled")


def _row(parent, label: str, initial: str = "", width: int = 34):
    """生成一行 "标签 + 输入框", 返回输入框。"""
    frame = ttk.Frame(parent)
    frame.pack(fill="x", padx=8, pady=3)
    ttk.Label(frame, text=label, width=26, anchor="w").pack(side="left")
    var = tk.StringVar(value=initial)
    entry = ttk.Entry(frame, textvariable=var, width=width,
                      font=("Consolas", 10))
    entry.pack(side="left", fill="x", expand=True)
    entry.var = var  # type: ignore[attr-defined]
    return entry


# --------------------------------------------------------------------------
# 第 1 关: 基本测试(GUI 加解密)
# --------------------------------------------------------------------------
class Level1Tab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        ttk.Label(self, text="第 1 关 · 基本测试: 8-bit 明文 + 10-bit 密钥 → 8-bit 密文",
                  font=("Microsoft YaHei", 12, "bold")).pack(anchor="w", pady=(0, 6))

        self.pt = _row(self, "明文 (8-bit 二进制)", DEFAULT_PT)
        self.key = _row(self, "密钥 (10-bit 二进制)", DEFAULT_KEY)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=6)
        ttk.Button(btns, text="加密 →", command=self.do_encrypt).pack(side="left")
        ttk.Button(btns, text="← 解密", command=self.do_decrypt).pack(side="left", padx=6)
        ttk.Button(btns, text="逐步跟踪 (供手算比对)",
                   command=self.do_trace).pack(side="left", padx=6)
        ttk.Button(btns, text="随机明文/密钥", command=self.do_random).pack(side="left", padx=6)
        ttk.Button(btns, text="清空", command=self.do_clear).pack(side="left")

        self.out = _row(self, "结果 (二进制)")
        self.out_hex = _row(self, "结果 (十六进制)")
        for w in (self.out, self.out_hex):
            w.configure(state="readonly")

        ttk.Label(self, text="过程明细 / 中间状态").pack(anchor="w", padx=8, pady=(8, 2))
        self.log = _scrolled_text(self, height=16)
        _set_text(self.log, "点击“加密”或“逐步跟踪”后在此显示中间状态。\n"
                            "提示: 本作业的 SBox2 与标准 S-DES 的 S1 不同, "
                            "因此公开资料里的标准测试向量不适用。")

    # -- 输入解析 ---------------------------------------------------------
    def _read(self):
        pt = _clean_bits(self.pt.var.get())
        key = _clean_bits(self.key.var.get())
        if len(pt) != core.BLOCK_BITS:
            raise ValueError(f"明文必须是 {core.BLOCK_BITS} bit, 当前 {len(pt)} bit")
        if len(key) != core.KEY_BITS:
            raise ValueError(f"密钥必须是 {core.KEY_BITS} bit, 当前 {len(key)} bit")
        return pt, key

    def _show(self, pt: str, key: str, ct: str):
        self.out.var.set(ct)
        self.out_hex.var.set(format(int(ct, 2), "02X"))

    def do_encrypt(self):
        try:
            pt, key = self._read()
            ct = core.encrypt(pt, key)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("输入错误", str(exc))
            return
        self._show(pt, key, ct)
        k1, k2 = core.key_schedule(key)
        _set_text(self.log, "\n".join([
            f"密钥 K      = {key}   (0x{int(key, 2):03X})",
            f"明文 P      = {pt}   (0x{int(pt, 2):02X})",
            f"子密钥 K1   = {core.int_to_bits(k1, 8)}",
            f"子密钥 K2   = {core.int_to_bits(k2, 8)}",
            "",
            f"密文 C      = {ct}   (0x{int(ct, 2):02X})",
            "",
            "解密校验: " + core.decrypt(ct, key) + "  (应与明文一致)",
        ]))

    def do_decrypt(self):
        try:
            pt, key = self._read()
            back = core.decrypt(pt, key)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("输入错误", str(exc))
            return
        self._show(pt, key, back)
        _set_text(self.log, f"把输入当作密文解密:\n\n  密文 C = {pt}\n  密钥 K = {key}\n"
                            f"  明文 P = {back}  (0x{int(back, 2):02X})")

    def do_trace(self):
        try:
            pt, key = self._read()
            info = core.trace(pt, key)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("输入错误", str(exc))
            return
        self._show(pt, key, info["IP^-1(...) = C"])
        lines = [f"{name:<24}= {value}" for name, value in info.items()]
        _set_text(self.log, "\n".join(lines))

    def do_random(self):
        import random
        self.pt.var.set(core.int_to_bits(random.randrange(_BLOCK_SPACE), 8))
        self.key.var.set(core.int_to_bits(random.randrange(_KEY_SPACE), 10))
        self.do_encrypt()

    def do_clear(self):
        self.pt.var.set("")
        self.key.var.set("")
        self.out.var.set("")
        self.out_hex.var.set("")
        _set_text(self.log, "")


# --------------------------------------------------------------------------
# 第 2 关: 交叉测试(规范化测试向量)
# --------------------------------------------------------------------------
class Level2Tab(ttk.Frame):
    """生成/比对规范化测试向量, 用于与同组同学(异构平台)交叉验证。"""

    HEADER = "pt,key,ct"

    def __init__(self, master):
        super().__init__(master, padding=10)
        ttk.Label(self, text="第 2 关 · 交叉测试: 导出/比对规范化测试向量",
                  font=("Microsoft YaHei", 12, "bold")).pack(anchor="w", pady=(0, 6))
        ttk.Label(self, text=("测试向量格式: 每行 pt,key,ct (均为 0/1 串, 逗号分隔, 可含表头)。\n"
                              "与对方程序互导该文件, 若逐行一致即说明算法流程与转换单元实现相同。"),
                  justify="left").pack(anchor="w", padx=8)

        cfg = ttk.Frame(self)
        cfg.pack(fill="x", padx=8, pady=6)
        ttk.Label(cfg, text="生成条数").pack(side="left")
        self.count = tk.StringVar(value="64")
        ttk.Entry(cfg, textvariable=self.count, width=8).pack(side="left", padx=4)
        ttk.Label(cfg, text="   密钥(留空表示只用下方固定密钥)").pack(side="left")
        self.fixed_key = tk.StringVar(value=DEFAULT_KEY)
        ttk.Entry(cfg, textvariable=self.fixed_key, width=14,
                  font=("Consolas", 10)).pack(side="left", padx=4)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=4)
        ttk.Button(btns, text="生成并保存 CSV…", command=self.generate).pack(side="left")
        ttk.Button(btns, text="导入对方文件并比对…", command=self.compare).pack(side="left", padx=6)
        ttk.Button(btns, text="复制到剪贴板", command=self.copy).pack(side="left")

        self.log = _scrolled_text(self, height=22)
        _set_text(self.log, "生成的向量会显示在这里。")

    def _make_vectors(self):
        import random
        random.seed(20261008)
        n = int(self.count.get())
        key_text = _clean_bits(self.fixed_key.get())
        lines = [self.HEADER]
        for _ in range(n):
            if key_text:
                if len(key_text) != core.KEY_BITS:
                    raise ValueError(f"固定密钥必须是 {core.KEY_BITS} bit")
                key = key_text
            else:
                key = core.int_to_bits(random.randrange(_KEY_SPACE), 10)
            pt = core.int_to_bits(random.randrange(_BLOCK_SPACE), 8)
            lines.append(f"{pt},{key},{core.encrypt(pt, key)}")
        return lines

    def generate(self):
        try:
            lines = self._make_vectors()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("错误", str(exc))
            return
        self._lines = lines
        _set_text(self.log, "\n".join(lines))
        path = filedialog.asksaveasfilename(
            title="保存测试向量", defaultextension=".csv",
            initialfile="sdes_test_vectors.csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(lines) + "\n")
            messagebox.showinfo("完成", f"已保存 {len(lines) - 1} 条向量到:\n{path}")

    def copy(self):
        lines = getattr(self, "_lines", None)
        if not lines:
            messagebox.showinfo("提示", "请先生成测试向量。")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        messagebox.showinfo("完成", "已复制到剪贴板。")

    def compare(self):
        path = filedialog.askopenfilename(title="选择对方的测试向量文件",
                                          filetypes=[("CSV 文件", "*.csv"),
                                                     ("所有文件", "*.*")])
        if not path:
            return
        ok = bad = 0
        details = []
        with open(path, "r", encoding="utf-8-sig") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.replace("\t", ",").split(",")]
                if len(parts) < 3 or parts[0].lower() in ("pt", "plaintext", "明文"):
                    continue
                pt, key, ct = parts[0], parts[1], parts[2]
                try:
                    mine = core.encrypt(_clean_bits(pt), _clean_bits(key))
                except Exception as exc:  # noqa: BLE001
                    details.append(f"第 {lineno} 行: 解析失败 ({exc})")
                    bad += 1
                    continue
                if mine == _clean_bits(ct):
                    ok += 1
                else:
                    bad += 1
                    details.append(f"第 {lineno} 行不一致: pt={pt} key={key} "
                                   f"对方={ct} 本程序={mine}")
        summary = [f"比对文件: {path}", f"一致 {ok} 条, 不一致 {bad} 条", ""]
        if bad == 0:
            summary.append("结论: 全部一致 —— 双方算法流程与转换单元实现相同, 通过交叉测试。")
        else:
            summary.append("前若干条差异:")
            summary.extend(details[:30])
        _set_text(self.log, "\n".join(summary))


# --------------------------------------------------------------------------
# 第 3 关: 扩展功能(ASCII 字符串 + TCP Socket)
# --------------------------------------------------------------------------
class Level3Tab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        ttk.Label(self, text="第 3 关 · 扩展功能: ASCII/UTF-8 字符串加密 + TCP Socket 通信",
                  font=("Microsoft YaHei", 12, "bold")).pack(anchor="w", pady=(0, 6))

        self.key = _row(self, "密钥 (10-bit 二进制)", DEFAULT_KEY)

        ttk.Label(self, text="明文文本 (按 1 Byte 分组加密)").pack(anchor="w", padx=8, pady=(6, 0))
        self.text = tk.Text(self, height=5, font=("Microsoft YaHei", 10))
        self.text.pack(fill="x", padx=8)
        self.text.insert("1.0", "This is a test")

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=6)
        ttk.Button(btns, text="加密 →", command=self.encrypt).pack(side="left")
        ttk.Button(btns, text="← 解密", command=self.decrypt).pack(side="left", padx=6)
        ttk.Button(btns, text="发送到 TCP 服务端…", command=self.send_tcp).pack(side="left", padx=6)

        ttk.Label(self, text="密文 (十六进制)").pack(anchor="w", padx=8)
        self.cipher = tk.Text(self, height=4, font=("Consolas", 10), background="#f3f7ff")
        self.cipher.pack(fill="x", padx=8)

        ttk.Label(self, text="说明 / 通信日志").pack(anchor="w", padx=8, pady=(8, 2))
        self.log = _scrolled_text(self, height=10)
        _set_text(self.log,
                  "加密: 明文 → UTF-8 字节 → 每字节一个 8-bit 分组 → S-DES → 十六进制密文。\n"
                  "解密: 十六进制密文 → 分组解密 → 字节 → UTF-8 文本。\n\n"
                  "TCP 演示: 先在命令行启动服务端  python -m sdes.server\n"
                  "然后在此填写主机/端口并点击“发送到 TCP 服务端”。\n"
                  "协议: 每行一条  <命令> <参数>, 命令为 ENC(加密) 或 DEC(解密)。")

        net = ttk.Frame(self)
        net.pack(fill="x", padx=8, pady=4)
        ttk.Label(net, text="主机").pack(side="left")
        self.host = tk.StringVar(value="127.0.0.1")
        ttk.Entry(net, textvariable=self.host, width=14).pack(side="left", padx=4)
        ttk.Label(net, text="端口").pack(side="left")
        self.port = tk.StringVar(value="50007")
        ttk.Entry(net, textvariable=self.port, width=8).pack(side="left", padx=4)

        self.worker = _Worker(self)

    def _key(self) -> str:
        key = _clean_bits(self.key.var.get())
        if len(key) != core.KEY_BITS:
            raise ValueError(f"密钥必须是 {core.KEY_BITS} bit, 当前 {len(key)} bit")
        return key

    def encrypt(self):
        try:
            key = self._key()
            plain = self.text.get("1.0", "end").rstrip("\n")
            ct = codec.encrypt_text_hex(plain, key)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("错误", str(exc))
            return
        self.cipher.delete("1.0", "end")
        self.cipher.insert("1.0", ct)
        _set_text(self.log, f"明文 {len(plain.encode('utf-8'))} 字节 → 密文 {len(ct) // 2} 字节\n"
                            f"密文(hex) = {ct}\n\n"
                            f"解密回环校验: {codec.decrypt_hex_text(ct, key)}")

    def decrypt(self):
        try:
            key = self._key()
            ct = _clean_bits(self.cipher.get("1.0", "end"))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("错误", str(exc))
            return
        try:
            plain = codec.decrypt_hex_text(ct, key)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("解密失败", f"{exc}\n(密文长度须为偶数, 且由 16 进制字符组成)")
            return
        self.text.delete("1.0", "end")
        self.text.insert("1.0", plain)
        _set_text(self.log, f"解密成功: {len(plain.encode('utf-8'))} 字节")

    def send_tcp(self):
        try:
            key = self._key()
            plain = self.text.get("1.0", "end").rstrip("\n")
            host, port = self.host.get().strip(), int(self.port.get())
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("错误", str(exc))
            return
        log = self.log
        _set_text(log, f"连接 {host}:{port} …")

        def work():
            import socket
            lines = []
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.settimeout(5)
                fp = sock.makefile("rwb")
                ct = codec.encrypt_text_hex(plain, key)
                request = f"DEC {ct}\n"
                fp.write(request.encode("utf-8"))
                fp.flush()
                reply = fp.readline().decode("utf-8").strip()
                lines.append(f"→ 本地加密: {ct}")
                lines.append(f"→ 发送: DEC {ct}")
                lines.append(f"← 服务端解密结果: {reply}")
                # 校验: 客户端本地解密同一段密文, 应与服务端返回一致
                lines.append(f"   本地解密校验: {codec.decrypt_hex_text(ct, key)}")
                return "\n".join(lines)

        def done(result):
            self.cipher.delete("1.0", "end")
            self.cipher.insert("1.0", codec.encrypt_text_hex(plain, key))
            _set_text(log, result + "\n\n提示: 若失败, 请先运行 python -m sdes.server")

        def fail(exc):
            _set_text(log, f"通信失败: {exc}\n\n请先启动服务端: python -m sdes.server")

        self.worker.run(work, done, fail)


# --------------------------------------------------------------------------
# 第 4 关: 暴力破解
# --------------------------------------------------------------------------
class Level4Tab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        ttk.Label(self, text="第 4 关 · 暴力破解: 由明文-密文对穷举 10-bit 密钥",
                  font=("Microsoft YaHei", 12, "bold")).pack(anchor="w", pady=(0, 6))
        ttk.Label(self, text=("填入已知的明文/密文对(二进制, 逗号分隔)。可填多对, 用 ; 分隔。\n"
                              "例: 10010111,00111000 ; 00000000,01010010"),
                  justify="left").pack(anchor="w", padx=8)

        self.pairs_box = tk.Text(self, height=4, font=("Consolas", 10))
        self.pairs_box.pack(fill="x", padx=8, pady=4)
        self.pairs_box.insert("1.0", f"{DEFAULT_PT},{core.encrypt(DEFAULT_PT, DEFAULT_KEY)}")

        cfg = ttk.Frame(self)
        cfg.pack(fill="x", padx=8, pady=4)
        ttk.Label(cfg, text="线程数").pack(side="left")
        self.workers = tk.StringVar(value="8")
        ttk.Entry(cfg, textvariable=self.workers, width=6).pack(side="left", padx=4)
        ttk.Label(cfg, text="每块大小").pack(side="left")
        self.chunk = tk.StringVar(value="64")
        ttk.Entry(cfg, textvariable=self.chunk, width=6).pack(side="left", padx=4)
        ttk.Button(cfg, text="随机生成一对(已知真钥匙)",
                   command=self.random_pair).pack(side="left", padx=8)
        self.use_threads = tk.BooleanVar(value=True)
        ttk.Checkbutton(cfg, text="多线程", variable=self.use_threads).pack(side="left")

        run = ttk.Frame(self)
        run.pack(fill="x", padx=8, pady=4)
        ttk.Button(run, text="开始破解", command=self.start).pack(side="left")
        self.bar = ttk.Progressbar(run, length=340, maximum=_KEY_SPACE)
        self.bar.pack(side="left", padx=8)
        self.status = ttk.Label(run, text="就绪")
        self.status.pack(side="left")

        self.log = _scrolled_text(self, height=14)
        _set_text(self.log, f"密钥空间 2^10 = {_KEY_SPACE} 个候选。\n"
                            "单对明文-密文平均留下约 4 个候选密钥; 两对即可几乎唯一确定。")
        self.worker = _Worker(self)
        self.truth = None

    def random_pair(self):
        import random
        truth = random.randrange(_KEY_SPACE)
        pt = random.randrange(_BLOCK_SPACE)
        ct = core.encrypt_int(pt, truth)
        self.pairs_box.delete("1.0", "end")
        self.pairs_box.insert("1.0", f"{core.int_to_bits(pt, 8)},{core.int_to_bits(ct, 8)}")
        self.truth = truth
        _set_text(self.log, f"已生成样本, 真钥匙(仅供核对, 程序不知道) = "
                            f"{core.int_to_bits(truth, 10)}")

    def _parse_pairs(self):
        raw = self.pairs_box.get("1.0", "end")
        pairs = []
        for chunk in raw.replace("\n", ";").split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = [p for p in chunk.replace(" ", "").split(",") if p]
            if len(parts) != 2:
                raise ValueError(f"无法解析明文-密文对: {chunk!r}")
            pt, ct = parts
            if len(pt) != 8 or len(ct) != 8:
                raise ValueError(f"明文与密文都必须是 8 bit: {chunk!r}")
            pairs.append((int(pt, 2), int(ct, 2)))
        if not pairs:
            raise ValueError("请至少填写一对明文-密文")
        return pairs

    def start(self):
        try:
            pairs = self._parse_pairs()
            workers = int(self.workers.get())
            chunk = int(self.chunk.get())
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("输入错误", str(exc))
            return
        if self.worker.busy:
            return
        self.bar.configure(value=0)
        self.status.configure(text="破解中…")
        use_threads = self.use_threads.get()
        t0 = time.perf_counter()

        def progress(tried, total):
            self.worker.widget.after(0, lambda: self.bar.configure(value=tried))

        def work():
            if use_threads:
                return brute_force_threaded(pairs, workers=workers, chunk=chunk,
                                            progress=progress)
            return brute_force(pairs, progress=progress)

        def done(res):
            wall = (time.perf_counter() - t0) * 1000
            keys = [core.int_to_bits(k, 10) for k in res["keys"]]
            self.bar.configure(value=_KEY_SPACE)
            self.status.configure(text=f"完成, 用时 {wall:.1f} ms")
            lines = [
                f"输入对: " + ", ".join(f"{core.int_to_bits(p, 8)}→{core.int_to_bits(c, 8)}"
                                       for p, c in pairs),
                f"线程数: {res.get('workers', 1) if use_threads else 1}"
                f"    分块: {res.get('chunks', '-')}",
                f"尝试密钥数: {res['tried']} / {_KEY_SPACE}",
                f"核心计时 elapsed: {res['elapsed'] * 1000:.3f} ms    "
                f"速率: {res['rate']:.0f} 次/秒",
                f"界面往返用时: {wall:.3f} ms",
                "",
                f"候选密钥 {len(keys)} 个: {', '.join(keys)}",
            ]
            if self.truth is not None:
                hit = core.int_to_bits(self.truth, 10) in keys
                lines.append(f"真钥匙 = {core.int_to_bits(self.truth, 10)}   "
                             f"{'✓ 已在候选集中' if hit else '✗ 不在候选集中'}")
            if len(keys) == 1:
                lines.append("唯一确定密钥。")
            else:
                lines.append(f"仍有 {len(keys)} 个候选 —— 再增加一对明文-密文可进一步收敛。")
            _set_text(self.log, "\n".join(lines))

        def fail(exc):
            self.status.configure(text="失败")
            messagebox.showerror("破解失败", str(exc))

        self.worker.run(work, done, fail)


# --------------------------------------------------------------------------
# 第 5 关: 封闭测试(密钥碰撞分析)
# --------------------------------------------------------------------------
class Level5Tab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        ttk.Label(self, text="第 5 关 · 封闭测试: 是否存在多个密钥得到相同密文?",
                  font=("Microsoft YaHei", 12, "bold")).pack(anchor="w", pady=(0, 6))
        ttk.Label(self, text=("对每个明文 P, 枚举全部 1024 个密钥并统计密文分布; 同时检查"
                              "是否存在行为完全相同的“等价密钥类”。"),
                  justify="left").pack(anchor="w", padx=8)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=6)
        ttk.Button(btns, text="运行全空间分析 (1024×256)", command=self.run_full).pack(side="left")
        ttk.Button(btns, text="理论结论 (文字报告)", command=self.show_report).pack(side="left", padx=6)
        self.status = ttk.Label(btns, text="就绪")
        self.status.pack(side="left", padx=8)

        self.log = _scrolled_text(self, height=24)
        _set_text(self.log,
                  "待分析。点击“运行全空间分析”将枚举 1024 个密钥 × 256 个明文 = 262144 次加密。")
        self.worker = _Worker(self)

    def show_report(self):
        _set_text(self.log, collision_report(0))

    def run_full(self):
        if self.worker.busy:
            return
        self.status.configure(text="枚举中…")

        def work():
            t0 = time.perf_counter()
            stats = analyze_collisions()
            classes = equivalent_key_classes()
            return stats, classes, (time.perf_counter() - t0) * 1000

        def done(payload):
            stats, classes, ms = payload
            per = stats["per_plaintext"]
            maxes = [v["max"] for v in per.values()]
            avgs = [v["avg_keys_per_cipher"] for v in per.values()]
            lines = [
                "—— 全空间枚举结果 ——",
                f"枚举规模: {stats['total_pairs']} 对 (1024 密钥 × 256 明文), 用时 {ms:.1f} ms",
                f"全局等价密钥类: {len(classes)} 组"
                + ("  (本算法不存在)" if not classes else ""),
                "",
                "对单个明文 P:",
                f"  平均可产生不同密文的个数: {sum(v['distinct'] for v in per.values()) / len(per):.3f}"
                f"   (上界 256)",
                f"  最大“多密钥→同一密文”桶: {stats['max_bucket']} 个密钥",
                f"  各明文最大桶的最小值: {min(maxes)}",
                f"  平均每密文对应候选密钥数: {sum(avgs) / len(avgs):.3f}"
                f"   (理论值 1024/256 = 4)",
                "",
                "桶大小分布 (桶大小 → 出现次数):",
            ]
            for size in sorted(stats["buckets"]):
                lines.append(f"  {size:>3} 个密钥 → 同一密文 : {stats['buckets'][size]} 次")
            lines += [
                "",
                "—— 结论 ——",
                "1. 密文空间 256 < 密钥空间 1024, 由鸽巢原理, 对任意明文必存在 Ki ≠ Kj 使",
                "   E(Ki, P) = E(Kj, P)。因此“多密钥→同一密文”不可避免。",
                "2. 但不存在两个密钥对所有明文都完全相同(-全局等价类为 0): P8 虽然丢弃了 P10",
                "   左半第 1、2 位(K1 不用), 但 K2 在左移 2 位后重新用到这两位, 右半 5 位则始终被使用,",
                "   故 1024 个主密钥映射到 1024 个互不相同的 (K1, K2)。",
                "3. 实用含义: 只用一个明文-密文对无法唯一确定密钥(平均约 4 个候选);",
                "   增加第二对明文-密文即可迅速收敛到唯一密钥。",
            ]
            self.status.configure(text=f"完成 ({ms:.0f} ms)")
            _set_text(self.log, "\n".join(lines))

        def fail(exc):
            self.status.configure(text="失败")
            messagebox.showerror("分析失败", str(exc))

        self.worker.run(work, done, fail)


# --------------------------------------------------------------------------
def main() -> int:
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("980x760")
    try:
        root.call("tk", "scaling", 1.2)
    except tk.TclError:
        pass

    style = ttk.Style()
    if "vista" in style.theme_names():
        style.theme_use("vista")

    header = ttk.Frame(root, padding=(12, 10, 12, 4))
    header.pack(fill="x")
    ttk.Label(header, text="S-DES 算法实现与加解密演示",
              font=("Microsoft YaHei", 16, "bold")).pack(anchor="w")
    ttk.Label(header, text="分组 8-bit · 密钥 10-bit · 轮数 2 · 注意: 本作业 SBox2 与标准 S-DES 的 S1 不同",
              foreground="#555").pack(anchor="w")

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=10, pady=8)
    for title, cls in (("第1关 基本测试", Level1Tab),
                       ("第2关 交叉测试", Level2Tab),
                       ("第3关 扩展功能", Level3Tab),
                       ("第4关 暴力破解", Level4Tab),
                       ("第5关 封闭测试", Level5Tab)):
        nb.add(cls(nb), text=title)

    ttk.Label(root, text="运行: python -m sdes.gui    |    命令行服务端: python -m sdes.server",
              foreground="#777").pack(anchor="w", padx=14, pady=(0, 8))
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
