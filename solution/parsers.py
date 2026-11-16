"""逐字节增量解析器：严格解析器与带三处明确缺陷的教学解析器。

设计要点：
- 逐字节增量喂入（feed），错误位置一律为原始流绝对偏移。
- 严格解析器 StrictParser：完整实现协议全部约束。
- 教学解析器 TeachingParser：与严格解析器共享同一状态机核心，
  通过三个显式开关引入三处明确缺陷：
    缺陷1 LENGTH_RETRY = True   长度少算一字节：严格帧定界下 CRC 校验失败时，
                                按“发送方少算了类型字节（LEN 只计载荷）”重试，
                                若重试校验通过则接受该帧。
    缺陷2 CHECK_DUPLICATE_KEY = False   重复关键标签 0x01 接受。
    缺陷3 MAX_DEPTH = 9         嵌套深度多接受一层（严格为 8）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .protocol import (
    CRC_LEN,
    HEADER_LEN,
    MAX_DEPTH,
    MAX_FRAME_TOTAL,
    MAX_LEN_FIELD,
    TAG_KEY,
    TAG_NESTED,
    TLVNode,
    crc32,
)

# 错误码（解析层）
E_LENGTH_INVALID = "LENGTH_INVALID"        # LEN < 1（连类型字节都容纳不下）
E_FRAME_TOO_LARGE = "FRAME_TOO_LARGE"      # LEN 超出 64KiB 单帧上限
E_CRC_MISMATCH = "CRC_MISMATCH"            # CRC32 校验失败
E_TLV_TRUNCATED = "TLV_TRUNCATED"          # TLV 头/值越出所在容器
E_DEPTH_EXCEEDED = "DEPTH_EXCEEDED"        # 嵌套深度超限
E_DUPLICATE_TAG = "DUPLICATE_TAG"          # 同一层关键标签 0x01 重复


class ParseFault(Exception):
    """内部使用：携带错误码与绝对偏移。"""

    def __init__(self, code: str, offset: int):
        super().__init__(f"{code}@{offset}")
        self.code = code
        self.offset = offset


@dataclass
class FrameResult:
    """一帧成功解析的结果。"""
    start: int                 # 帧在流中的绝对起始偏移
    end: int                   # 帧结束偏移（不含），即消费边界
    msg_type: int
    tree: List[TLVNode]        # 顶层 TLV 树（未知标签作为不透明值保留）
    via_length_retry: bool = False   # 教学缺陷1：是否经“长度重试”路径接受


def validate_tlvs(payload: bytes, abs_base: int, check_dup: bool,
                  max_depth: int) -> List[TLVNode]:
    """校验载荷中的 TLV 序列，返回 TLV 树；失败抛 ParseFault（绝对偏移）。

    abs_base: payload[0] 在原始流中的绝对偏移。
    """
    def walk(start: int, end: int, depth: int) -> List[TLVNode]:
        nodes: List[TLVNode] = []
        seen_key = False
        pos = start
        while pos < end:
            if end - pos < 3:
                raise ParseFault(E_TLV_TRUNCATED, abs_base + pos)
            tag = payload[pos]
            tlen = int.from_bytes(payload[pos + 1:pos + 3], "big")
            if pos + 3 + tlen > end:
                raise ParseFault(E_TLV_TRUNCATED, abs_base + pos)
            if depth > max_depth:
                raise ParseFault(E_DEPTH_EXCEEDED, abs_base + pos)
            if tag == TAG_KEY:
                if check_dup and seen_key:
                    raise ParseFault(E_DUPLICATE_TAG, abs_base + pos)
                seen_key = True
            node = TLVNode(tag=tag,
                           value=bytes(payload[pos + 3:pos + 3 + tlen]),
                           children=None, offset=abs_base + pos)
            if tag == TAG_NESTED:
                node.children = walk(pos + 3, pos + 3 + tlen, depth + 1)
            nodes.append(node)
            pos += 3 + tlen
        return nodes

    return walk(0, len(payload), 0)


class StrictParser:
    """严格解析器：逐字节增量解析，完整实施协议约束。

    类属性为缺陷开关；严格解析器全部处于关闭/严格值。
    """

    CHECK_DUPLICATE_KEY = True   # 缺陷2开关：同一层 0x01 是否查重
    MAX_DEPTH = MAX_DEPTH        # 缺陷3开关：允许的最大 TLV 深度
    LENGTH_RETRY = False         # 缺陷1开关：长度少算一字节时是否重试接受

    def __init__(self) -> None:
        self._frame = bytearray()   # 当前帧已累积字节
        self._stage = "len"         # 'len' -> 'body' -> （可选）'retry'
        self._len: Optional[int] = None
        self._abs = 0               # 下一个待消费字节的绝对偏移
        self._frame_start = 0       # 当前帧起始绝对偏移
        self.consumed = 0           # 已完成帧消费到的绝对偏移（消费边界）
        self.frames: List[FrameResult] = []
        self.error: Optional[Tuple[str, int]] = None   # (错误码, 绝对偏移)
        self._finished = False

    # ---- 增量接口 ---------------------------------------------------------
    def feed(self, data: bytes) -> None:
        """逐字节增量喂入。任意分块方式不影响结论。"""
        for i in range(len(data)):
            self._feed_byte(data[i])

    def finish(self) -> None:
        """标记输入结束（EOF）。之后可读取 verdict。"""
        self._finished = True

    # ---- 状态查询 ---------------------------------------------------------
    @property
    def pending(self) -> bool:
        """是否处于帧中途（finish 后仍为 True 即“不完整”）。"""
        return self.error is None and (bool(self._frame) or self._stage != "len")

    # ---- 内部状态机 -------------------------------------------------------
    def _feed_byte(self, b: int) -> None:
        if self.error is not None:
            return  # 出错后停机：后续字节不再消费
        if not self._frame:
            self._frame_start = self._abs
        self._frame.append(b)
        self._abs += 1
        self._progress()

    def _progress(self) -> None:
        if self._stage == "len":
            if len(self._frame) < HEADER_LEN:
                return
            self._len = int.from_bytes(self._frame[:HEADER_LEN], "big")
            if self._len < 1:
                return self._fail(E_LENGTH_INVALID, self._frame_start)
            if self._len > MAX_LEN_FIELD:
                return self._fail(E_FRAME_TOO_LARGE, self._frame_start)
            self._stage = "body"
        if self._stage == "body":
            want = self._len + HEADER_LEN + CRC_LEN
            if len(self._frame) < want:
                return
            crc_off = HEADER_LEN + self._len
            expect = int.from_bytes(self._frame[crc_off:crc_off + CRC_LEN], "big")
            actual = crc32(bytes(self._frame[HEADER_LEN:crc_off]))
            if expect == actual:
                return self._accept(payload=bytes(self._frame[HEADER_LEN + 1:crc_off]),
                                    via_retry=False, total=want)
            if self.LENGTH_RETRY:
                # 缺陷1：按“LEN 少算类型字节”重试 —— 需要再读 1 字节
                self._stage = "retry"
                return self._progress()
            return self._fail(E_CRC_MISMATCH, self._frame_start + crc_off)
        if self._stage == "retry":
            want = self._len + HEADER_LEN + CRC_LEN + 1
            if want > MAX_FRAME_TOTAL:
                # 重试帧同样受 64KiB 上限约束
                return self._fail(E_FRAME_TOO_LARGE, self._frame_start)
            if len(self._frame) < want:
                return
            crc_off = HEADER_LEN + 1 + self._len   # 载荷按 LEN 字节解释
            expect = int.from_bytes(self._frame[crc_off:crc_off + CRC_LEN], "big")
            actual = crc32(bytes(self._frame[HEADER_LEN:crc_off]))
            if expect == actual:
                return self._accept(payload=bytes(self._frame[HEADER_LEN + 1:crc_off]),
                                    via_retry=True, total=want)
            return self._fail(E_CRC_MISMATCH, self._frame_start + crc_off)

    def _accept(self, payload: bytes, via_retry: bool, total: int) -> None:
        abs_base = self._frame_start + HEADER_LEN + 1
        try:
            tree = validate_tlvs(payload, abs_base,
                                 self.CHECK_DUPLICATE_KEY, self.MAX_DEPTH)
        except ParseFault as f:
            return self._fail(f.code, f.offset)
        self.frames.append(FrameResult(
            start=self._frame_start, end=self._frame_start + total,
            msg_type=self._frame[HEADER_LEN], tree=tree,
            via_length_retry=via_retry))
        self.consumed = self._frame_start + total
        self._frame.clear()
        self._stage = "len"
        self._len = None

    def _fail(self, code: str, offset: int) -> None:
        self.error = (code, offset)


class TeachingParser(StrictParser):
    """教学解析器：带三处明确缺陷（与严格解析器共享状态机核心）。

    缺陷1 LENGTH_RETRY=True  —— 长度少算一字节：严格定界 CRC 失败时，
        按“LEN 未计入类型字节”的假设重试，重试校验通过即接受。
    缺陷2 CHECK_DUPLICATE_KEY=False —— 重复关键标签 0x01 接受。
    缺陷3 MAX_DEPTH=9 —— 嵌套深度多接受一层（严格为 8）。
    """

    CHECK_DUPLICATE_KEY = False
    MAX_DEPTH = 9
    LENGTH_RETRY = True
