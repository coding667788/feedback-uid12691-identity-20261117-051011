"""教学解析器三处缺陷的单元测试。"""
from __future__ import annotations

import unittest

from solution.differ import run_parser
from solution.generator import CaseGenerator, KIND_STRUCTURE
from solution.parsers import StrictParser, TeachingParser
from solution.sampledata import build_samples

SAMPLES = build_samples()


def teaching_outcome(data):
    return run_parser(TeachingParser(), data)


def strict_outcome(data):
    return run_parser(StrictParser(), data)


class TestTeachingDefects(unittest.TestCase):
    def test_defect1_length_undercount_accepted(self):
        data = SAMPLES["length_undercount.bin"]
        strict = strict_outcome(data)
        teaching = teaching_outcome(data)
        self.assertEqual(strict.outcome, "reject")      # 严格：定界错位 CRC 失败
        self.assertEqual(teaching.outcome, "accept")    # 教学：重试后接受
        self.assertTrue(teaching.via_length_retry)
        self.assertEqual(teaching.consumed, len(data))

    def test_defect2_duplicate_key_tag_accepted(self):
        data = SAMPLES["dup_tag.bin"]
        self.assertEqual(strict_outcome(data).outcome, "reject")
        self.assertEqual(teaching_outcome(data).outcome, "accept")

    def test_defect3_depth_9_accepted(self):
        data = SAMPLES["deep_nest.bin"]
        self.assertEqual(strict_outcome(data).outcome, "reject")
        self.assertEqual(teaching_outcome(data).outcome, "accept")

    def test_valid_frames_behave_identically(self):
        """缺陷不应改变合法帧的行为：生成器保持结构用例两者结论一致。"""
        gen = CaseGenerator(20261117)
        checked = 0
        for i in range(200):
            data, kind = gen.case(i)
            if kind != KIND_STRUCTURE:
                continue
            s, t = strict_outcome(data), teaching_outcome(data)
            self.assertEqual(s.diff_key(), t.diff_key(),
                             f"合法帧 {i} 两解析器结论不一致")
            self.assertEqual(s.outcome, "accept")
            checked += 1
        self.assertGreater(checked, 50)               # 确实覆盖了足够多样本

    def test_bad_crc_not_silently_accepted(self):
        data = SAMPLES["bad_crc.bin"]
        self.assertEqual(strict_outcome(data).outcome, "reject")
        # 教学解析器重试也需要额外字节；EOF 时只能是不完整，绝不能接受
        self.assertEqual(teaching_outcome(data).outcome, "incomplete")


if __name__ == "__main__":
    unittest.main()
