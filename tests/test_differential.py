"""差分测试验收：固定种子稳定发现三类缺陷；随机异常不算发现。"""
from __future__ import annotations

import unittest

from solution.differ import (
    CAT_DUPLICATE_KEY_TAG,
    CAT_LENGTH_UNDERCOUNT,
    CAT_NESTING_DEPTH,
    INTERNAL_ERROR,
    classify,
    run_pair,
)
from solution.parsers import StrictParser, TeachingParser
from solution.workbench import run_fuzz
from tests.util import fresh_tmp

SEED = 12691
CASES = 60


class CrashingParser(StrictParser):
    """模拟随机异常的解析器：喂入即抛错。"""

    def feed(self, data: bytes) -> None:
        raise RuntimeError("boom")


class TestFixedSeedFindsAllDefects(unittest.TestCase):
    """验收场景：固定种子稳定发现三类缺陷。"""

    @classmethod
    def setUpClass(cls):
        cls.findings_dir = fresh_tmp("fuzz_fixed_seed")
        cls.summary = run_fuzz(SEED, CASES, cls.findings_dir, minimize=False)

    def test_all_three_defect_categories_found(self):
        cats = self.summary["differentials"]["by_category"]
        self.assertIn(CAT_LENGTH_UNDERCOUNT, cats)
        self.assertIn(CAT_DUPLICATE_KEY_TAG, cats)
        self.assertIn(CAT_NESTING_DEPTH, cats)
        # 固定种子的精确计数（可重放证据）
        self.assertEqual(cats[CAT_LENGTH_UNDERCOUNT], 11)
        self.assertEqual(cats[CAT_DUPLICATE_KEY_TAG], 9)
        self.assertEqual(cats[CAT_NESTING_DEPTH], 19)

    def test_no_internal_errors_and_clean_controls(self):
        self.assertEqual(self.summary["internal_errors"], 0)
        self.assertGreater(self.summary["clean"], 0)   # 保持结构用例无差分

    def test_fixed_seed_replayable(self):
        """同一种子重跑，汇总逐字段一致。"""
        again_dir = fresh_tmp("fuzz_fixed_seed_again")
        again = run_fuzz(SEED, CASES, again_dir, minimize=False)
        self.assertEqual(self.summary["differentials"], again["differentials"])
        self.assertEqual(self.summary["clean"], again["clean"])
        self.assertEqual(
            [(f["case_index"], f["category"]) for f in self.summary["findings"]],
            [(f["case_index"], f["category"]) for f in again["findings"]])


class TestExceptionsAreNotFindings(unittest.TestCase):
    def test_random_exception_not_counted_as_differential(self):
        data = b"\x00\x00\x00\x05\x01abc"
        strict, teaching = run_pair(
            data, strict_cls=CrashingParser, teaching_cls=TeachingParser)
        self.assertEqual(strict.outcome, "internal_error")
        cls = classify(strict, teaching)
        self.assertIsNotNone(cls)
        self.assertEqual(cls.category, INTERNAL_ERROR)

    def test_both_sides_crash_still_internal(self):
        strict, teaching = run_pair(
            b"x", strict_cls=CrashingParser, teaching_cls=CrashingParser)
        cls = classify(strict, teaching)
        self.assertEqual(cls.category, INTERNAL_ERROR)


if __name__ == "__main__":
    unittest.main()
