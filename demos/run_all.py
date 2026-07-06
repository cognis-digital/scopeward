"""Run every scopeward demo in order; exit non-zero if any demo fails.

    python demos/run_all.py

Each demo is a standalone module invoked in-process. Output is streamed so the
run reads like a guided tour of the tool. Runs fully offline.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))


def demo_modules() -> list[str]:
    names = sorted(
        p.stem
        for p in HERE.glob("*.py")
        if p.stem[0].isdigit()  # numbered demos only
    )
    return names


def main() -> int:
    names = demo_modules()
    failures: list[str] = []
    for name in names:
        mod = importlib.import_module(name)
        try:
            rc = mod.main()
        except Exception as exc:  # pragma: no cover - surfaced below
            print(f"\n[{name}] raised {type(exc).__name__}: {exc}")
            rc = 1
        if rc != 0:
            failures.append(name)

    print("\n" + "#" * 68)
    if failures:
        print(f"FAILED demos: {failures}")
        return 1
    print(f"ALL {len(names)} DEMOS PASSED")
    print("#" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
