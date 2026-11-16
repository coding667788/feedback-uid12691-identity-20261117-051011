"""测试公共工具。"""
from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


def fresh_tmp(name: str) -> Path:
    """在 tests/.tmp 下创建干净的临时目录（所有文件操作局限在项目内）。"""
    path = TMP_ROOT / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path
