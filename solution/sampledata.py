"""项目内样例数据构造（确定性，可重复生成）。

样例覆盖：合法帧、嵌套帧、三类缺陷触发帧、坏 CRC、截短帧、多帧流。
生成入口：python -m solution --make-samples --output-dir samples
"""
from __future__ import annotations

from pathlib import Path

from .protocol import (
    CONVENTION_STRICT,
    CONVENTION_UNDERCOUNTED,
    TAG_KEY,
    TAG_NESTED,
    crc32,
    encode_frame,
    encode_tlv,
    encode_tlvs,
    TLVNode,
)


def build_samples() -> dict:
    """返回 {文件名: 字节}，内容完全确定。"""
    valid_minimal = encode_frame(
        0x01, encode_tlvs([TLVNode(TAG_KEY, b"v1"), TLVNode(0x02, b"hello")]),
        CONVENTION_STRICT)

    nested_payload = encode_tlvs([
        TLVNode(TAG_KEY, b"root"),
        TLVNode(TAG_NESTED, b"", children=[
            TLVNode(0x02, b"child"),
            TLVNode(TAG_NESTED, b"", children=[TLVNode(0x7F, b"opaque")]),
        ]),
        TLVNode(0x7F, b"\x00\x01\x02"),   # 未知标签：不透明保留
    ])
    valid_nested = encode_frame(0x02, nested_payload, CONVENTION_STRICT)

    dup_tag = encode_frame(
        0x01, encode_tlvs([TLVNode(TAG_KEY, b"a"), TLVNode(TAG_KEY, b"b")]),
        CONVENTION_STRICT)

    deep_payload = encode_tlv(0x02, b"leaf")
    for _ in range(9):                    # 叶子落到深度 9，超出严格的 8 层
        deep_payload = encode_tlv(TAG_NESTED, deep_payload)
    deep_nest = encode_frame(0x03, deep_payload, CONVENTION_STRICT)

    undercounted_payload = encode_tlvs([TLVNode(TAG_KEY, b"k"),
                                        TLVNode(0x02, b"data")])
    length_undercount = encode_frame(0x01, undercounted_payload,
                                     CONVENTION_UNDERCOUNTED)

    bad_crc = bytearray(valid_minimal)
    bad_crc[-1] ^= 0xFF                   # 破坏 CRC 最后一字节
    bad_crc = bytes(bad_crc)

    truncated = valid_minimal[:-2]        # 截短：缺 2 字节 CRC

    multi_frame = valid_minimal + dup_tag  # 多帧流：第二帧含重复关键标签

    return {
        "valid_minimal.bin": valid_minimal,
        "valid_nested.bin": valid_nested,
        "dup_tag.bin": dup_tag,
        "deep_nest.bin": deep_nest,
        "length_undercount.bin": length_undercount,
        "bad_crc.bin": bad_crc,
        "truncated.bin": truncated,
        "multi_frame.bin": multi_frame,
    }


def make_samples(output_dir: Path) -> list:
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, data in build_samples().items():
        (output_dir / name).write_bytes(data)
        written.append(name)
    return written
