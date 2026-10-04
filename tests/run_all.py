"""S-DES 作业统一测试入口。

一次运行全部测试模块并汇总结果。

用法（必须在项目根目录执行）::

    python -m tests.run_all
    python -m tests.run_all --skip-network     # 跳过第3关网络往返测试

退出码：0 = 全部通过；1 = 存在失败项。
"""

from __future__ import annotations

import argparse
import importlib
import io
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path

# 允许直接以脚本方式运行（python tests/run_all.py）时也能 import sdes
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

MODULES = (
    ("tests.test_all", "S-DES 算法 / 编解码 / 暴力破解 / 碰撞分析 自测套件"),
    ("tests.test_longkey", "第4关(进阶) 扩展密钥空间 (级联 S-DES) 自测套件"),
    ("tests.test_network", "第3关 TCP Socket 加密通信 往返测试"),
    ("tests.test_webapp", "第6关(附加) 网页版界面 HTTP 接口 自测套件"),
)

# --skip-network 时应跳过的模块
_NETWORK_MODULES = {"tests.test_network", "tests.test_webapp"}


def _run_module(name: str, title: str) -> tuple[bool, str, float]:
    """导入并运行单个测试模块的 main()，返回 (是否通过, 输出文本, 耗时秒)."""
    started = time.perf_counter()
    buffer = io.StringIO()
    try:
        module = importlib.import_module(name)
    except Exception as exc:  # 导入失败（语法错误、依赖缺失）
        return False, f"导入 {name} 失败: {exc!r}", time.perf_counter() - started

    entry = getattr(module, "main", None)
    if entry is None:
        return False, f"{name} 缺少 main() 入口", time.perf_counter() - started

    with redirect_stdout(buffer):
        try:
            code = entry()
        except SystemExit as exc:  # main() 调用 sys.exit
            code = exc.code if isinstance(exc.code, int) else 1
        except Exception as exc:  # 模块内部未捕获异常
            buffer.write(f"\n[EXC] {name} 运行期间抛出异常: {exc!r}\n")
            code = 1
    return code in (None, 0), buffer.getvalue(), time.perf_counter() - started


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="S-DES 作业统一测试入口")
    parser.add_argument("--skip-network", action="store_true",
                        help="跳过第3关 TCP 与网页版 (需要开监听端口的) 测试")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="只显示汇总，不显示各模块明细")
    args = parser.parse_args(argv)

    selected = [
        (name, title) for name, title in MODULES
        if not (args.skip_network and name in _NETWORK_MODULES)
    ]

    print("=" * 72)
    print("S-DES 作业自测总入口 —— 统一测试报告")
    print(f"项目根目录: {_ROOT}")
    print(f"Python: {sys.version.split()[0]}  ({sys.executable})")
    print("=" * 72)

    report: list[tuple[str, str, bool, float]] = []
    for name, title in selected:
        print(f"\n>>> 运行 {name} —— {title}")
        ok, output, elapsed = _run_module(name, title)
        report.append((name, title, ok, elapsed))
        if args.quiet:
            tail = [ln for ln in output.splitlines() if "结果" in ln or "FAIL" in ln]
            for line in tail:
                print("    " + line)
        else:
            print(output.rstrip("\n"))

    total = time.perf_counter()
    print("\n" + "=" * 72)
    print("汇总")
    print("-" * 72)
    failed = []
    for name, title, ok, elapsed in report:
        flag = "[PASS]" if ok else "[FAIL]"
        print(f"  {flag}  {name:<24} {elapsed * 1000:8.1f} ms   {title}")
        if not ok:
            failed.append(name)
    print("-" * 72)

    # 说明用的编译信息（不参与判定）
    print(f"  通过 {len(report) - len(failed)}/{len(report)} 个测试模块")
    elapsed_all = sum(e for _, _, _, e in report)
    print(f"  测试用例总耗时 {elapsed_all * 1000:.1f} ms")

    if failed:
        print(f"\n结果: 存在失败模块 -> {', '.join(failed)}")
        return 1
    print("\n结果: 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
