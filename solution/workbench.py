"""工作台编排：fuzz 循环、findings 持久化、断点恢复与重放。

findings 目录布局：
    finding-<case_index:06d>-<category>.json   每个差分一份
    state.json                                 {"seed":..., "next_index":...}

每个 finding 记录：种子、用例序号、原样字节(hex)、差分分类、最小化结果、
重放命令。由于第 i 个用例仅取决于 (seed, i)，进程中断后按 state.json 的
next_index 恢复，生成序列与不中断完全一致。
"""
from __future__ import annotations

import json
import random
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .differ import (
    INTERNAL_ERROR,
    Classification,
    classify,
    classify_bytes,
    run_pair,
)
from .generator import CaseGenerator, derive_case_seed
from .minimizer import Minimizer
from .parsers import StrictParser, TeachingParser

STATE_FILE = "state.json"


def _chunk_sizes_for(seed: int, index: int, data_len: int) -> List[int]:
    """每个用例的确定性随机分块（验证分块不影响结论；两解析器同块喂入）。"""
    rng = random.Random(derive_case_seed(seed, index) ^ 0x5EED)
    sizes: List[int] = []
    remaining = data_len
    while remaining > 0:
        n = rng.randint(1, 16)
        sizes.append(n)
        remaining -= n
    return sizes


def finding_name(case_index: int, category: str) -> str:
    return f"finding-{case_index:06d}-{category}.json"


def run_fuzz(seed: int, cases: int, findings_dir: Path, start_index: int = 0,
             minimize: bool = True) -> dict:
    """运行差分模糊测试，返回汇总 dict（同时写入 findings 目录）。"""
    findings_dir.mkdir(parents=True, exist_ok=True)
    gen = CaseGenerator(seed)
    minimizer = Minimizer()
    by_category: Dict[str, int] = {}
    clean = 0
    internal = 0
    findings: List[dict] = []

    for index in range(start_index, start_index + cases):
        data, kind = gen.case(index)
        chunks = _chunk_sizes_for(seed, index, len(data))
        strict, teaching = run_pair(data, chunk_sizes=chunks)
        cls = classify(strict, teaching)
        if cls is None:
            clean += 1
            continue
        if cls.category == INTERNAL_ERROR:
            internal += 1
            continue
        by_category[cls.category] = by_category.get(cls.category, 0) + 1

        record = {
            "id": f"seed{seed}-{index:06d}-{cls.category}",
            "seed": seed,
            "case_index": index,
            "case_kind": kind,
            "category": cls.category,
            "classification": {
                "strict": list(cls.strict),
                "teaching": list(cls.teaching),
                "consumed_equal": cls.consumed_equal,
            },
            "original_hex": data.hex(),
            "original_size": len(data),
        }
        if minimize:
            res = minimizer.minimize(data, cls)
            record["minimized_hex"] = res.minimized.hex()
            record["minimized_size"] = len(res.minimized)
            record["locally_minimal"] = res.locally_minimal
            record["reductions"] = res.reductions
        fname = finding_name(index, cls.category)
        record["replay_command"] = (
            f"python -m solution --replay "
            f"{(findings_dir / fname).as_posix()}")
        (findings_dir / fname).write_text(
            json.dumps(record, indent=2, ensure_ascii=False),
            encoding="utf-8")
        findings.append({
            "id": record["id"],
            "category": cls.category,
            "case_index": index,
            "file": fname,
            "original_size": record["original_size"],
            "minimized_size": record.get("minimized_size"),
            "locally_minimal": record.get("locally_minimal"),
        })

    state = {"seed": seed, "next_index": start_index + cases}
    (findings_dir / STATE_FILE).write_text(json.dumps(state), encoding="utf-8")
    return {
        "seed": seed,
        "start_index": start_index,
        "cases_run": cases,
        "clean": clean,
        "internal_errors": internal,
        "differentials": {
            "total": sum(by_category.values()),
            "by_category": by_category,
        },
        "findings": findings,
        "state_file": str((findings_dir / STATE_FILE).as_posix()),
    }


def load_resume_index(findings_dir: Path) -> Optional[int]:
    """读取断点状态；不存在返回 None。"""
    state_path = findings_dir / STATE_FILE
    if not state_path.exists():
        return None
    state = json.loads(state_path.read_text(encoding="utf-8"))
    return int(state["next_index"])


def replay_finding(path: Path) -> dict:
    """重放一个 finding：重新差分原样字节与最小化字节，核对分类。"""
    record = json.loads(path.read_text(encoding="utf-8"))
    original = bytes.fromhex(record["original_hex"])
    expected = Classification(
        record["category"],
        tuple(record["classification"]["strict"]),
        tuple(record["classification"]["teaching"]),
        bool(record["classification"]["consumed_equal"]),
    )
    cls_orig = classify_bytes(original)
    orig_ok = cls_orig is not None and cls_orig.key() == expected.key()

    result = {
        "finding_id": record["id"],
        "category": record["category"],
        "original": {
            "reproduced": orig_ok,
            "classification": _cls_dict(cls_orig),
        },
    }
    if "minimized_hex" in record:
        minimized = bytes.fromhex(record["minimized_hex"])
        cls_min = classify_bytes(minimized)
        min_ok = cls_min is not None and cls_min.key() == expected.key()
        locally = Minimizer().check_local_minimality(minimized, expected.key())
        result["minimized"] = {
            "reproduced": min_ok,
            "locally_minimal": locally,
            "size": len(minimized),
        }
    reproduced = orig_ok and result.get("minimized", {}).get("reproduced", True)
    result["verdict"] = "reproduced" if reproduced else "not_reproduced"
    return result


def _cls_dict(cls: Optional[Classification]) -> Optional[dict]:
    if cls is None:
        return None
    return {"category": cls.category, "strict": list(cls.strict),
            "teaching": list(cls.teaching),
            "consumed_equal": cls.consumed_equal}


def parse_file(path: Path, parser_name: str,
               chunk_sizes: Optional[List[int]]) -> dict:
    """parse 模式：用指定解析器解析一个二进制文件，输出结论细节。"""
    from .differ import run_parser  # 局部导入避免循环

    data = path.read_bytes()
    cls = {"strict": StrictParser, "teaching": TeachingParser}[parser_name]
    outcome = run_parser(cls(), data, chunk_sizes)
    return {
        "parser": parser_name,
        "input_file": str(path),
        "input_size": len(data),
        "outcome": outcome.outcome,
        "error": ({"code": outcome.code, "offset": outcome.offset}
                  if outcome.code else None),
        "consumed": outcome.consumed,
        "frames": outcome.frames,
        "via_length_retry": outcome.via_length_retry,
    }
