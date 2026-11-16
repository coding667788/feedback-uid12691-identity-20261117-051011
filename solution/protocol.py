"""协议常量、CRC、帧/TLV 编解码与结构解析工具。仅使用标准库。"""
from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from typing import List, Optional

# ---- 协议常量 -------------------------------------------------------------
HEADER_LEN = 4                     # LEN 字段字节数
TYPE_LEN = 1                       # TYPE 字段字节数
CRC_LEN = 4                        # CRC32 字段字节数
MAX_FRAME_TOTAL = 65536            # 单帧 64KiB（含 LEN 与 CRC）
MAX_LEN_FIELD = MAX_FRAME_TOTAL - HEADER_LEN - CRC_LEN   # LEN 字段最大值 65528

TAG_KEY = 0x01        # 关键标签：同一层最多出现一次
TAG_NESTED = 0x20     # 嵌套 TLV：VALUE 本身为 TLV 序列
MAX_DEPTH = 8         # 顶层深度为 0，允许的最大 TLV 深度（深度 0..8 合法）

# 长度字段编码约定（用于最小化时的“调整长度”）：
#   "strict"       -> LEN = 1 + len(payload)（计入类型字节，规范约定）
#   "undercounted" -> LEN = len(payload)（少算类型字节，触发教学缺陷1的构造约定）
CONVENTION_STRICT = "strict"
CONVENTION_UNDERCOUNTED = "undercounted"


def crc32(data: bytes) -> int:
    """CRC32（zlib 语义），覆盖 TYPE 与 TLV 载荷。"""
    return zlib.crc32(data) & 0xFFFFFFFF


def encode_tlv(tag: int, value: bytes) -> bytes:
    if not 0 <= tag <= 0xFF:
        raise ValueError("tag out of range")
    if len(value) > 0xFFFF:
        raise ValueError("tlv value too large")
    return bytes([tag]) + len(value).to_bytes(2, "big") + bytes(value)


def encode_frame(msg_type: int, payload: bytes,
                 convention: str = CONVENTION_STRICT) -> bytes:
    """按给定长度约定编码一帧。CRC 始终覆盖 TYPE||payload。"""
    if not 0 <= msg_type <= 0xFF:
        raise ValueError("msg_type out of range")
    if convention == CONVENTION_STRICT:
        len_field = TYPE_LEN + len(payload)
    elif convention == CONVENTION_UNDERCOUNTED:
        len_field = len(payload)
    else:
        raise ValueError(f"unknown length convention: {convention}")
    if not 0 <= len_field <= MAX_LEN_FIELD:
        raise ValueError("frame too large")
    body = bytes([msg_type]) + bytes(payload)
    return (len_field.to_bytes(4, "big") + body
            + crc32(body).to_bytes(4, "big"))


@dataclass
class TLVNode:
    """TLV 树节点。children 为 None 表示不透明值；非 None 表示嵌套（tag 0x20）。"""
    tag: int
    value: bytes
    children: Optional[List["TLVNode"]] = None
    offset: int = 0          # 解析时填写：tag 字节的偏移（相对基准由调用方决定）

    def encode(self) -> bytes:
        if self.children is not None:
            return encode_tlv(self.tag, encode_tlvs(self.children))
        return encode_tlv(self.tag, self.value)


def encode_tlvs(nodes: List[TLVNode]) -> bytes:
    return b"".join(n.encode() for n in nodes)


def parse_tlvs_structural(payload: bytes, offset_base: int = 0
                          ) -> Optional[List[TLVNode]]:
    """纯结构解析（容忍重复关键标签与超深嵌套），供最小化/生成器使用。

    仅检查 TLV 头是否完整、值是否越界。失败返回 None。
    """
    def walk(start: int, end: int) -> Optional[List[TLVNode]]:
        nodes: List[TLVNode] = []
        pos = start
        while pos < end:
            if end - pos < 3:
                return None
            tag = payload[pos]
            tlen = int.from_bytes(payload[pos + 1:pos + 3], "big")
            if pos + 3 + tlen > end:
                return None
            value = bytes(payload[pos + 3:pos + 3 + tlen])
            node = TLVNode(tag=tag, value=value, children=None,
                           offset=offset_base + pos)
            if tag == TAG_NESTED:
                children = walk(pos + 3, pos + 3 + tlen)
                if children is None:
                    return None
                node.children = children
            nodes.append(node)
            pos += 3 + tlen
        return nodes

    return walk(0, len(payload))


def tree_max_depth(nodes: List[TLVNode], depth: int = 0) -> int:
    """树中节点的最大深度（nodes 本身处于 depth 层）。"""
    best = depth - 1 if not nodes else depth
    for n in nodes:
        best = max(best, depth)
        if n.children is not None:
            best = max(best, tree_max_depth(n.children, depth + 1))
    return best
