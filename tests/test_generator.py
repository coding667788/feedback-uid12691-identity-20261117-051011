"""生成器确定性与变异语义测试。"""
from __future__ import annotations

import unittest

from solution.differ import (
    CAT_DUPLICATE_KEY_TAG,
    CAT_LENGTH_UNDERCOUNT,
    CAT_NESTING_DEPTH,
    classify_bytes,
)
from solution.generator import (
    KIND_BREAK_DEPTH,
    KIND_BREAK_DUP,
    KIND_BREAK_LENGTH,
    KIND_STRUCTURE,
    CaseGenerator,
)
from solution.parsers import StrictParser
from solution.differ import run_parser


class TestGeneratorDeterminism(unittest.TestCase):
    def test_same_seed_same_sequence(self):
        g1 = CaseGenerator(12691)
        g2 = CaseGenerator(12691)
        for i in range(50):
            self.assertEqual(g1.case(i), g2.case(i), f"用例 {i} 不一致")

    def test_resume_does_not_change_sequence(self):
        """模拟中断恢复：从任意位置重新生成，序列与不中断完全一致。"""
        full = CaseGenerator(777)
        expected = [full.case(i) for i in range(30)]
        for resume_at in (1, 7, 13, 29):
            resumed = CaseGenerator(777)
            for i in range(resume_at, 30):
                self.assertEqual(resumed.case(i), expected[i],
                                 f"从 {resume_at} 恢复后用例 {i} 改变")

    def test_different_seed_different_sequence(self):
        g1, g2 = CaseGenerator(1), CaseGenerator(2)
        same = sum(1 for i in range(50) if g1.case(i) == g2.case(i))
        self.assertLess(same, 5)


class TestMutationSemantics(unittest.TestCase):
    def test_structure_mutations_stay_strictly_valid(self):
        gen = CaseGenerator(4242)
        checked = 0
        for i in range(200):
            data, kind = gen.case(i)
            if kind != KIND_STRUCTURE:
                continue
            out = run_parser(StrictParser(), data)
            self.assertEqual(out.outcome, "accept",
                             f"保持结构用例 {i} 被严格解析器拒绝: {out.code}")
            self.assertEqual(out.consumed, len(data))
            checked += 1
        self.assertGreater(checked, 50)

    def test_break_mutations_hit_expected_defects(self):
        """每种破坏单一约束的变异都触发对应差分分类。"""
        gen = CaseGenerator(4242)
        seen = {}
        for i in range(300):
            data, kind = gen.case(i)
            if kind == KIND_STRUCTURE:
                continue
            cls = classify_bytes(data)
            self.assertIsNotNone(cls, f"破坏用例 {i}({kind}) 未产生差分")
            seen.setdefault(kind, cls.category)
        self.assertEqual(seen[KIND_BREAK_LENGTH], CAT_LENGTH_UNDERCOUNT)
        self.assertEqual(seen[KIND_BREAK_DUP], CAT_DUPLICATE_KEY_TAG)
        self.assertEqual(seen[KIND_BREAK_DEPTH], CAT_NESTING_DEPTH)


if __name__ == "__main__":
    unittest.main()
