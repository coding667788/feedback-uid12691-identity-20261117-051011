"""差分比较器：并行运行严格/教学解析器，比较接受状态与消费边界。

判差规则（仅以下两类归为差分，随机异常不算发现）：
- 接受状态不同（accept / reject / incomplete 任一不一致，或拒绝错误码不同）
- 消费边界不同（已接受帧数或已消费字节数不同）
任一解析器抛出未捕获异常 -> internal_error，单独计数，不计入差分。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple, Type

from .parsers import (
    E_CRC_MISMATCH,
    E_DEPTH_EXCEEDED,
    E_DUPLICATE_TAG,
    E_FRAME_TOO_LARGE,
    E_LENGTH_INVALID,
    StrictParser,
    TeachingParser,
)

# 差分分类
CAT_LENGTH_UNDERCOUNT = "length_undercount"      # 缺陷1：长度少算一字节
CAT_DUPLICATE_KEY_TAG = "duplicate_key_tag"      # 缺陷2：重复关键标签接受
CAT_NESTING_DEPTH = "nesting_depth"              # 缺陷3：嵌套深度多接受一层
CAT_CONSUMED_MISMATCH = "consumed_mismatch"      # 仅消费边界不同
CAT_OTHER = "other"                              # 其他接受状态差异
INTERNAL_ERROR = "internal_error"                # 随机异常：不算发现

OUTCOME_ACCEPT = "accept"
OUTCOME_REJECT = "reject"
OUTCOME_INCOMPLETE = "incomplete"
OUTCOME_INTERNAL = "internal_error"


@dataclass(frozen=True)
class RunOutcome:
    """单个解析器跑完一段输入后的结论。"""
    outcome: str                 # accept / reject / incomplete / internal_error
    code: Optional[str]          # 拒绝时的错误码
    offset: Optional[int]        # 拒绝时的绝对偏移
    consumed: int                # 已完成帧消费到的绝对偏移（消费边界）
    frames: int                  # 已接受帧数
    via_length_retry: bool = False
    input_len: int = 0           # 本次输入总长度（用于归一化签名）

    def diff_key(self) -> Tuple:
        """差分判定键（绝对值）：接受状态 + 消费边界。"""
        return (self.outcome, self.code, self.consumed, self.frames)

    def sig(self) -> Tuple:
        """保分类签名（归一化）：最小化前后可稳定比较。

        consumed 用“是否消费了全部输入”归一，避免尺寸变化导致签名漂移。
        """
        return (self.outcome, self.code, self.frames,
                self.consumed == self.input_len)


@dataclass(frozen=True)
class Classification:
    """一次差分的分类结果。最小化必须完整保留该分类（key 完全相等）。"""
    category: str
    strict: Tuple                # RunOutcome.sig()
    teaching: Tuple
    consumed_equal: bool         # 两侧消费边界是否一致（捕获消费边界差分）

    def key(self) -> Tuple:
        return (self.category, self.strict, self.teaching, self.consumed_equal)


def run_parser(parser: StrictParser, data: bytes,
               chunk_sizes: Optional[List[int]] = None) -> RunOutcome:
    """按给定分块喂入并取结论。chunk_sizes=None 表示整块喂入。

    解析器内部异常被捕获并映射为 OUTCOME_INTERNAL（随机异常不算发现）。
    """
    try:
        if chunk_sizes is None:
            parser.feed(data)
        else:
            pos = 0
            for n in chunk_sizes:
                if pos >= len(data):
                    break
                parser.feed(data[pos:pos + n])
                pos += n
            if pos < len(data):
                parser.feed(data[pos:])
        parser.finish()
    except Exception as exc:  # noqa: BLE001 —— 随机异常必须被隔离
        return RunOutcome(OUTCOME_INTERNAL, type(exc).__name__, None,
                          getattr(parser, "consumed", 0),
                          len(getattr(parser, "frames", [])),
                          input_len=len(data))
    if parser.error is not None:
        code, offset = parser.error
        return RunOutcome(OUTCOME_REJECT, code, offset, parser.consumed,
                          len(parser.frames), input_len=len(data))
    if parser.pending:
        return RunOutcome(OUTCOME_INCOMPLETE, None, None, parser.consumed,
                          len(parser.frames), input_len=len(data))
    via_retry = any(f.via_length_retry for f in parser.frames)
    return RunOutcome(OUTCOME_ACCEPT, None, None, parser.consumed,
                      len(parser.frames), via_retry, input_len=len(data))


def run_pair(data: bytes,
             strict_cls: Type[StrictParser] = StrictParser,
             teaching_cls: Type[StrictParser] = TeachingParser,
             chunk_sizes: Optional[List[int]] = None
             ) -> Tuple[RunOutcome, RunOutcome]:
    """同一输入分别跑严格/教学解析器，返回 (strict, teaching) 结论。"""
    return (run_parser(strict_cls(), data, chunk_sizes),
            run_parser(teaching_cls(), data, chunk_sizes))


def classify(strict: RunOutcome, teaching: RunOutcome) -> Optional[Classification]:
    """比较两个结论。无差异返回 None；有差异返回分类。

    internal_error 不算发现：返回 category=INTERNAL_ERROR 的分类由调用方
    单独计数（不入 findings）。
    """
    if strict.outcome == OUTCOME_INTERNAL or teaching.outcome == OUTCOME_INTERNAL:
        return Classification(INTERNAL_ERROR, strict.sig(), teaching.sig(),
                              strict.consumed == teaching.consumed)
    if strict.diff_key() == teaching.diff_key():
        return None
    category = _infer_category(strict, teaching)
    return Classification(category, strict.sig(), teaching.sig(),
                          strict.consumed == teaching.consumed)


def _infer_category(strict: RunOutcome, teaching: RunOutcome) -> str:
    if (strict.outcome == OUTCOME_REJECT
            and teaching.outcome == OUTCOME_ACCEPT):
        if strict.code in (E_CRC_MISMATCH, E_LENGTH_INVALID, E_FRAME_TOO_LARGE):
            return CAT_LENGTH_UNDERCOUNT
        if strict.code == E_DUPLICATE_TAG:
            return CAT_DUPLICATE_KEY_TAG
        if strict.code == E_DEPTH_EXCEEDED:
            return CAT_NESTING_DEPTH
        return CAT_OTHER
    if (strict.outcome == teaching.outcome
            and strict.code == teaching.code
            and (strict.consumed != teaching.consumed
                 or strict.frames != teaching.frames)):
        return CAT_CONSUMED_MISMATCH
    return CAT_OTHER


def classify_bytes(data: bytes, chunk_sizes: Optional[List[int]] = None
                   ) -> Optional[Classification]:
    """便捷入口：对一段字节直接做差分分类（最小化器使用固定分块保证确定）。"""
    strict, teaching = run_pair(data, chunk_sizes=chunk_sizes)
    return classify(strict, teaching)
