"""CLI 入口测试：python -m solution --input/--output、重放、恢复。"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from tests.util import REPO_ROOT, fresh_tmp


def run_cli(*args, cwd=REPO_ROOT):
    return subprocess.run(
        [sys.executable, "-m", "solution", *args],
        cwd=cwd, capture_output=True, text=True, timeout=300)


def write_cases(directory: Path, spec: dict) -> Path:
    path = directory / "cases.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


class TestCliFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = fresh_tmp("cli_fuzz")
        cls.cases = write_cases(cls.tmp, {
            "mode": "fuzz", "seed": 12691, "cases": 30,
            "findings_dir": "findings", "minimize": True,
        })
        cls.output = cls.tmp / "result.json"
        cls.proc = run_cli("--input", str(cls.cases),
                           "--output", str(cls.output))

    def test_exit_ok_and_schema(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        result = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["mode"], "fuzz")
        self.assertEqual(result["seed"], 12691)
        self.assertEqual(result["cases_run"], 30)
        self.assertEqual(result["internal_errors"], 0)
        cats = result["differentials"]["by_category"]
        self.assertIn("length_undercount", cats)
        self.assertIn("duplicate_key_tag", cats)
        self.assertIn("nesting_depth", cats)

    def test_findings_files_complete(self):
        result = json.loads(self.output.read_text(encoding="utf-8"))
        findings_dir = self.tmp / "findings"
        self.assertTrue((findings_dir / "state.json").exists())
        self.assertGreater(len(result["findings"]), 0)
        for f in result["findings"]:
            record = json.loads(
                (findings_dir / f["file"]).read_text(encoding="utf-8"))
            # 种子、原样字节、分类、重放命令必须保存
            self.assertEqual(record["seed"], 12691)
            self.assertIsInstance(record["case_index"], int)
            self.assertTrue(record["original_hex"])
            bytes.fromhex(record["original_hex"])      # 可解码
            self.assertIn("strict", record["classification"])
            self.assertIn("teaching", record["classification"])
            self.assertIn("python -m solution --replay",
                          record["replay_command"])
            self.assertTrue(record["locally_minimal"])

    def test_replay_reproduces(self):
        result = json.loads(self.output.read_text(encoding="utf-8"))
        finding = self.tmp / "findings" / result["findings"][0]["file"]
        replay_out = self.tmp / "replay_result.json"
        proc = run_cli("--replay", str(finding), "--output", str(replay_out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        replay = json.loads(replay_out.read_text(encoding="utf-8"))
        self.assertEqual(replay["verdict"], "reproduced")
        self.assertTrue(replay["original"]["reproduced"])
        self.assertTrue(replay["minimized"]["reproduced"])
        self.assertTrue(replay["minimized"]["locally_minimal"])


class TestCliResume(unittest.TestCase):
    """进程中断后恢复不得改变同一种子的生成序列。"""

    def test_resume_matches_uninterrupted_run(self):
        tmp = fresh_tmp("cli_resume")
        interrupted = tmp / "interrupted"
        fresh = tmp / "fresh"

        # 中断运行：先 10 个，再 resume 10 个
        c1 = write_cases(tmp, {"mode": "fuzz", "seed": 99, "cases": 10,
                               "findings_dir": str(interrupted),
                               "minimize": False})
        p1 = run_cli("--input", str(c1), "--output", str(tmp / "r1.json"))
        self.assertEqual(p1.returncode, 0, p1.stderr)
        c2 = write_cases(tmp, {"mode": "fuzz", "seed": 99, "cases": 10,
                               "findings_dir": str(interrupted),
                               "minimize": False, "resume": True})
        p2 = run_cli("--input", str(c2), "--output", str(tmp / "r2.json"))
        self.assertEqual(p2.returncode, 0, p2.stderr)

        # 不中断运行：一次 20 个
        c3 = write_cases(tmp, {"mode": "fuzz", "seed": 99, "cases": 20,
                               "findings_dir": str(fresh), "minimize": False})
        p3 = run_cli("--input", str(c3), "--output", str(tmp / "r3.json"))
        self.assertEqual(p3.returncode, 0, p3.stderr)

        def findings_of(directory: Path):
            out = {}
            for f in sorted(directory.glob("finding-*.json")):
                rec = json.loads(f.read_text(encoding="utf-8"))
                out[rec["case_index"]] = (rec["category"], rec["original_hex"])
            return out

        self.assertEqual(findings_of(interrupted), findings_of(fresh))
        state = json.loads((interrupted / "state.json").read_text())
        self.assertEqual(state["next_index"], 20)


class TestCliParseAndErrors(unittest.TestCase):
    def test_parse_mode_strict_and_teaching(self):
        tmp = fresh_tmp("cli_parse")
        for parser, expected in (("strict", "reject"), ("teaching", "accept")):
            cases = write_cases(tmp, {
                "mode": "parse", "parser": parser,
                "input_file": str(REPO_ROOT / "samples" / "dup_tag.bin"),
                "chunk_sizes": [1, 3, 2],
            })
            out = tmp / f"parse_{parser}.json"
            proc = run_cli("--input", str(cases), "--output", str(out))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["outcome"], expected)
            if expected == "reject":
                self.assertEqual(result["error"]["code"], "DUPLICATE_TAG")
                self.assertEqual(result["error"]["offset"], 9)

    def test_schema_error_exit_2(self):
        tmp = fresh_tmp("cli_err")
        bad = tmp / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        proc = run_cli("--input", str(bad), "--output", str(tmp / "r.json"))
        self.assertEqual(proc.returncode, 2)
        result = json.loads((tmp / "r.json").read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["code"], "E_SCHEMA")

    def test_missing_input_file_exit_2(self):
        tmp = fresh_tmp("cli_err2")
        cases = write_cases(tmp, {"mode": "parse", "parser": "strict",
                                  "input_file": "no_such_file.bin"})
        proc = run_cli("--input", str(cases), "--output", str(tmp / "r.json"))
        self.assertEqual(proc.returncode, 2)
        result = json.loads((tmp / "r.json").read_text(encoding="utf-8"))
        self.assertEqual(result["errors"][0]["code"], "E_INPUT")


if __name__ == "__main__":
    unittest.main()
