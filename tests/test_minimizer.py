"""最小化器测试：保分类、局部最小性（逐字节删除核查）。"""
from __future__ import annotations

import unittest

from solution.differ import classify_bytes
from solution.generator import (
    KIND_BREAK_DEPTH,
    KIND_BREAK_DUP,
    KIND_BREAK_LENGTH,
    CaseGenerator,
)
from solution.minimizer import Minimizer, frame_meta
from solution.protocol import encode_frame


def first_case_of(kind: str, seed: int = 12691):
    gen = CaseGenerator(seed)
    for i in range(500):
        data, k = gen.case(i)
        if k == kind:
            return data
    raise AssertionError(f"未找到 {kind} 用例")


class TestMinimizer(unittest.TestCase):
    def _minimize(self, data):
        cls = classify_bytes(data)
        self.assertIsNotNone(cls)
        result = Minimizer().minimize(data, cls)
        return cls, result

    def _check_categories(self, kind, expected_category):
        data = first_case_of(kind)
        cls, result = self._minimize(data)
        self.assertEqual(cls.category, expected_category)
        # 分类保留
        self.assertEqual(result.classification, cls.key())
        again = classify_bytes(result.minimized)
        self.assertIsNotNone(again)
        self.assertEqual(again.key(), cls.key())
        # 尺寸不增且确实缩小
        self.assertLess(len(result.minimized), len(data))
        # 局部最小性（最小化器自检）
        self.assertTrue(result.locally_minimal)
        return cls, result

    def test_length_undercount_minimized(self):
        self._check_categories(KIND_BREAK_LENGTH, "length_undercount")

    def test_duplicate_key_tag_minimized(self):
        self._check_categories(KIND_BREAK_DUP, "duplicate_key_tag")

    def test_nesting_depth_minimized(self):
        self._check_categories(KIND_BREAK_DEPTH, "nesting_depth")

    def test_byte_level_local_minimality(self):
        """验收场景：最小化结果逐字节删除检查局部最小性。"""
        for kind in (KIND_BREAK_LENGTH, KIND_BREAK_DUP, KIND_BREAK_DEPTH):
            data = first_case_of(kind)
            cls, result = self._minimize(data)
            meta = frame_meta(result.minimized)
            self.assertIsNotNone(meta)
            for j in range(len(meta.payload)):
                new_payload = meta.payload[:j] + meta.payload[j + 1:]
                cand = encode_frame(meta.msg_type, new_payload, meta.convention)
                after = classify_bytes(cand)
                self.assertTrue(
                    after is None or after.key() != cls.key(),
                    f"{kind}: 删除载荷字节 {j} 后仍复现分类，非局部最小")

    def test_minimizer_rejects_non_reproducing_input(self):
        data = first_case_of(KIND_BREAK_DUP)
        cls = classify_bytes(data)
        other = first_case_of(KIND_BREAK_DEPTH)
        with self.assertRaises(ValueError):
            Minimizer().minimize(other, cls)   # 分类不匹配：拒绝最小化

    def test_minimization_is_deterministic(self):
        data = first_case_of(KIND_BREAK_DEPTH)
        cls = classify_bytes(data)
        r1 = Minimizer().minimize(data, cls)
        r2 = Minimizer().minimize(data, cls)
        self.assertEqual(r1.minimized, r2.minimized)
        self.assertEqual(r1.reductions, r2.reductions)


if __name__ == "__main__":
    unittest.main()
