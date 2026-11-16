"""命令行入口与 cases.json 调度。

用法：
    python -m solution --input cases.json --output result.json
    python -m solution --replay findings/finding-000001-xxx.json [--output r.json]
    python -m solution --make-samples --output-dir samples

cases.json schema（相对路径相对 cases.json 所在目录解析）：
    {"mode": "fuzz",  "seed": int, "cases": int, "findings_dir": str,
     "minimize": bool, "resume": bool, "start_index": int}
    {"mode": "parse", "parser": "strict"|"teaching", "input_file": str,
     "chunk_sizes": [int, ...]}                      # chunk_sizes 可省略
    {"mode": "replay", "finding_file": str}

退出码：0 成功；2 输入/schema 错误（E_SCHEMA/E_INPUT/E_REPLAY）；1 内部错误。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .sampledata import make_samples
from .workbench import load_resume_index, parse_file, replay_finding, run_fuzz

E_SCHEMA = "E_SCHEMA"      # cases.json 缺失/非法
E_INPUT = "E_INPUT"        # 引用的输入文件不存在或不可读
E_REPLAY = "E_REPLAY"      # finding 文件非法
E_INTERNAL = "E_INTERNAL"  # 未捕获内部错误

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_INPUT = 2


class CliError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> dict:
    return {"status": "error", "errors": [{"code": code, "message": message}]}


def _resolve(base: Path, p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else (base / path)


def _require(cond: bool, code: str, message: str) -> None:
    if not cond:
        raise CliError(code, message)


def run_cases(cases_path: Path) -> dict:
    try:
        spec = json.loads(cases_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CliError(E_INPUT, f"cases 文件不存在: {cases_path}")
    except json.JSONDecodeError as exc:
        raise CliError(E_SCHEMA, f"cases.json 不是合法 JSON: {exc}")
    _require(isinstance(spec, dict), E_SCHEMA, "cases.json 顶层必须是对象")
    base = cases_path.resolve().parent
    mode = spec.get("mode")
    _require(mode in ("fuzz", "parse", "replay"),
             E_SCHEMA, "mode 必须是 fuzz/parse/replay")

    if mode == "fuzz":
        seed = spec.get("seed")
        cases = spec.get("cases")
        _require(isinstance(seed, int), E_SCHEMA, "fuzz 模式需要整数 seed")
        _require(isinstance(cases, int) and cases > 0,
                 E_SCHEMA, "fuzz 模式需要正整数 cases")
        findings_dir = _resolve(base, spec.get("findings_dir", "findings"))
        minimize = bool(spec.get("minimize", True))
        start_index = int(spec.get("start_index", 0))
        if spec.get("resume"):
            resumed = load_resume_index(findings_dir)
            _require(resumed is not None, E_INPUT,
                     f"resume 要求已存在状态文件: {findings_dir}")
            start_index = resumed
        summary = run_fuzz(seed, cases, findings_dir,
                           start_index=start_index, minimize=minimize)
        return {"status": "ok", "mode": "fuzz", **summary, "errors": []}

    if mode == "parse":
        parser = spec.get("parser", "strict")
        _require(parser in ("strict", "teaching"),
                 E_SCHEMA, "parser 必须是 strict/teaching")
        input_file = spec.get("input_file")
        _require(isinstance(input_file, str), E_SCHEMA,
                 "parse 模式需要 input_file")
        path = _resolve(base, input_file)
        _require(path.is_file(), E_INPUT, f"输入文件不存在: {path}")
        chunk_sizes = spec.get("chunk_sizes")
        if chunk_sizes is not None:
            _require(isinstance(chunk_sizes, list)
                     and all(isinstance(n, int) and n > 0 for n in chunk_sizes),
                     E_SCHEMA, "chunk_sizes 必须是正整数数组")
        detail = parse_file(path, parser, chunk_sizes)
        return {"status": "ok", "mode": "parse", **detail, "errors": []}

    # mode == "replay"
    finding_file = spec.get("finding_file")
    _require(isinstance(finding_file, str), E_SCHEMA,
             "replay 模式需要 finding_file")
    path = _resolve(base, finding_file)
    _require(path.is_file(), E_INPUT, f"finding 文件不存在: {path}")
    try:
        detail = replay_finding(path)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        raise CliError(E_REPLAY, f"finding 文件非法: {exc}")
    return {"status": "ok", "mode": "replay", **detail, "errors": []}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m solution",
                                 description="离线差分测试工作台")
    ap.add_argument("--input", help="cases.json 路径")
    ap.add_argument("--output", help="result.json 输出路径")
    ap.add_argument("--replay", help="直接重放一个 finding JSON")
    ap.add_argument("--make-samples", action="store_true",
                    help="生成样例二进制到 --output-dir")
    ap.add_argument("--output-dir", default="samples",
                    help="样例输出目录（配合 --make-samples）")
    args = ap.parse_args(argv)

    try:
        if args.make_samples:
            written = make_samples(Path(args.output_dir))
            result = {"status": "ok", "mode": "make-samples",
                      "written": written, "errors": []}
        elif args.replay:
            path = Path(args.replay)
            if not path.is_file():
                raise CliError(E_INPUT, f"finding 文件不存在: {path}")
            try:
                detail = replay_finding(path)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                raise CliError(E_REPLAY, f"finding 文件非法: {exc}")
            result = {"status": "ok", "mode": "replay", **detail, "errors": []}
        else:
            if not args.input:
                raise CliError(E_SCHEMA, "缺少 --input cases.json")
            result = run_cases(Path(args.input))
        exit_code = EXIT_OK
    except CliError as exc:
        result = _fail(exc.code, exc.message)
        exit_code = EXIT_INPUT
    except Exception as exc:  # noqa: BLE001 —— 兜底，绝不让异常裸奔
        result = _fail(E_INTERNAL, f"{type(exc).__name__}: {exc}")
        exit_code = EXIT_INTERNAL

    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
