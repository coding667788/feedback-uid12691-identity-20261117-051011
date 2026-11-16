"""严格解析器单元测试：增量解析、错误绝对偏移、分块不变性。"""
from __future__ import annotations

import random
import unittest

from solution.differ import run_parser
from solution.parsers import (
    E_CRC_MISMATCH,
    E_DEPTH_EXCEEDED,
    E_DUPLICATE_TAG,
    E_FRAME_TOO_LARGE,
    E_LENGTH_INVALID,
    E_TLV_TRUNCATED,
    StrictParser,
)
from solution.protocol import (
    TAG_KEY,
    TAG_NESTED,
    TLVNode,
    encode_frame,
    encode_tlv,
    encode_tlvs,
)
from solution.sampledata import build_samples

SAMPLES = build_samples()


def strict_outcome(data: bytes, chunk_sizes=None):
    return run_parser(StrictParser(), data, chunk_sizes)


class TestStrictParserBasics(unittest.TestCase):
    def test_valid_frame_accepted_and_consumed(self):
        data = SAMPLES["valid_minimal.bin"]
        out = strict_outcome(data)
        self.assertEqual(out.outcome, "accept")
        self.assertEqual(out.consumed, len(data))
        self.assertEqual(out.frames, 1)

    def test_unknown_tags_preserved_as_opaque(self):
        data = SAMPLES["valid_nested.bin"]
        parser = StrictParser()
        parser.feed(data)
        parser.finish()
        self.assertIsNone(parser.error)
        tree = parser.frames[0].tree
        tags = [n.tag for n in tree]
        self.assertIn(0x7F, tags)                      # 未知标签保留
        opaque = next(n for n in tree if n.tag == 0x7F)
        self.assertEqual(opaque.value, b"\x00\x01\x02")  # 不透明值原样
        self.assertIsNone(opaque.children)
        nested = next(n for n in tree if n.tag == TAG_NESTED)
        self.assertIsNotNone(nested.children)
        # 嵌套内层的未知标签同样保留
        inner = nested.children[1].children[0]
        self.assertEqual(inner.tag, 0x7F)
        self.assertEqual(inner.value, b"opaque")

    def test_duplicate_key_tag_rejected_at_absolute_offset(self):
        data = SAMPLES["dup_tag.bin"]
        out = strict_outcome(data)
        self.assertEqual(out.outcome, "reject")
        self.assertEqual(out.code, E_DUPLICATE_TAG)
        # 帧头 4 + 类型 1 + 第一个 TLV(1+2+1) = 第二个 0x01 标签偏移 9
        self.assertEqual(out.offset, 9)
        self.assertEqual(data[out.offset], TAG_KEY)

    def test_single_key_tag_allowed(self):
        payload = encode_tlvs([TLVNode(TAG_KEY, b"only")])
        out = strict_outcome(encode_frame(1, payload))
        self.assertEqual(out.outcome, "accept")

    def test_key_tag_allowed_in_different_levels(self):
        payload = encode_tlvs([
            TLVNode(TAG_KEY, b"top"),
            TLVNode(TAG_NESTED, b"", children=[TLVNode(TAG_KEY, b"inner")]),
        ])
        out = strict_outcome(encode_frame(1, payload))
        self.assertEqual(out.outcome, "accept")

    def test_depth_8_accepted_depth_9_rejected(self):
        leaf = encode_tlv(0x02, b"x")
        payload8 = leaf
        for _ in range(8):
            payload8 = encode_tlv(TAG_NESTED, payload8)
        out8 = strict_outcome(encode_frame(1, payload8))
        self.assertEqual(out8.outcome, "accept")

        payload9 = encode_tlv(TAG_NESTED, payload8)
        data9 = encode_frame(1, payload9)
        out9 = strict_outcome(data9)
        self.assertEqual(out9.outcome, "reject")
        self.assertEqual(out9.code, E_DEPTH_EXCEEDED)
        # 深度 9 的 TLV tag 绝对偏移：帧头4+类型1+9层嵌套头(每层3字节)
        self.assertEqual(out9.offset, 4 + 1 + 9 * 3)
        self.assertEqual(data9[out9.offset], 0x02)

    def test_crc_mismatch_offset_points_to_crc_field(self):
        data = bytearray(SAMPLES["valid_minimal.bin"])
        data[-1] ^= 0xFF
        out = strict_outcome(bytes(data))
        self.assertEqual(out.outcome, "reject")
        self.assertEqual(out.code, E_CRC_MISMATCH)
        len_field = int.from_bytes(data[:4], "big")
        self.assertEqual(out.offset, 4 + len_field)   # CRC 字段起始

    def test_length_invalid_and_too_large(self):
        out = strict_outcome(encode_frame(1, b"")[:0] + b"\x00\x00\x00\x00")
        self.assertEqual((out.outcome, out.code), ("reject", E_LENGTH_INVALID))
        self.assertEqual(out.offset, 0)

        too_big = (65536).to_bytes(4, "big")          # LEN > 65528
        out2 = strict_outcome(too_big)
        self.assertEqual((out2.outcome, out2.code),
                         ("reject", E_FRAME_TOO_LARGE))
        self.assertEqual(out2.offset, 0)

    def test_truncated_tlv_reported_at_tlv_offset(self):
        # 载荷：一个声明 10 字节值却只有 1 字节的 TLV
        payload = bytes([0x02, 0x00, 0x0A, 0xAA])
        out = strict_outcome(encode_frame(1, payload))
        self.assertEqual((out.outcome, out.code), ("reject", E_TLV_TRUNCATED))
        self.assertEqual(out.offset, 5)               # 帧头4+类型1

    def test_incomplete_stream_reports_incomplete(self):
        out = strict_outcome(SAMPLES["truncated.bin"])
        self.assertEqual(out.outcome, "incomplete")
        self.assertEqual(out.consumed, 0)

    def test_multi_frame_absolute_offsets(self):
        data = SAMPLES["multi_frame.bin"]
        first_len = len(SAMPLES["valid_minimal.bin"])
        out = strict_outcome(data)
        self.assertEqual(out.outcome, "reject")
        self.assertEqual(out.code, E_DUPLICATE_TAG)
        self.assertEqual(out.frames, 1)               # 第一帧已接受
        self.assertEqual(out.consumed, first_len)     # 消费边界在第一帧末尾
        self.assertEqual(out.offset, first_len + 9)   # 绝对偏移跨帧累加


class TestChunkingInvariance(unittest.TestCase):
    """验收场景：任意分块方式不得改变严格解析结论。"""

    CORPUS = [
        "valid_minimal.bin", "valid_nested.bin", "dup_tag.bin",
        "deep_nest.bin", "length_undercount.bin", "bad_crc.bin",
        "truncated.bin", "multi_frame.bin",
    ]

    def _chunkings(self, n: int):
        yield None                                   # 整块
        yield [1] * n                                # 逐字节
        yield [2] * n
        yield [3] * n
        yield [7] * n
        for seed in (1, 42, 2026):                   # 确定性随机分块
            rng = random.Random(seed)
            sizes, remaining = [], n
            while remaining > 0:
                k = rng.randint(1, 11)
                sizes.append(k)
                remaining -= k
            yield sizes

    def test_chunking_does_not_change_verdict(self):
        for name in self.CORPUS:
            data = SAMPLES[name]
            baseline = strict_outcome(data)
            for chunks in self._chunkings(len(data)):
                out = strict_outcome(data, chunks)
                label = "whole" if chunks is None else str(chunks[:4])
                self.assertEqual(
                    out.diff_key(), baseline.diff_key(),
                    f"{name} 分块 {label}... 结论改变: "
                    f"{out.diff_key()} != {baseline.diff_key()}")
                self.assertEqual(out.offset, baseline.offset)


if __name__ == "__main__":
    unittest.main()
