"""失败最小化器：在保留原差分分类的前提下缩小触发输入。

化简操作（每次化简后重新验证分类，分类键完全相等才接受）：
1. 截短（truncate）：删除尾部字节（原始截短，不修正）。
2. 删除 TLV（delete_tlv）：结构解析载荷，删除任一 TLV 节点后重新编码，
   并调整祖先嵌套长度、帧长度字段与 CRC32。
3. 单字节删除（delete_byte）：删除载荷区任一字节后按原长度约定
   重新调整长度字段与 CRC32。

循环至不动点后，再做一次完整的局部最小性核查（逐字节删除 + 逐 TLV 删除
+ 全部截短均不能复现原分类），核查结果写入 locally_minimal。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .differ import Classification, classify_bytes
from .protocol import (
    CONVENTION_STRICT,
    CONVENTION_UNDERCOUNTED,
    HEADER_LEN,
    TLVNode,
    encode_frame,
    encode_tlvs,
    parse_tlvs_structural,
)


@dataclass(frozen=True)
class FrameMeta:
    """从候选帧字节中还原出的 (类型, 载荷, 长度约定)。"""
    msg_type: int
    payload: bytes
    convention: str


@dataclass
class MinResult:
    original: bytes
    minimized: bytes
    classification: Tuple          # 保留的分类键
    locally_minimal: bool
    iterations: int
    reductions: List[str] = field(default_factory=list)   # 化简轨迹


def frame_meta(data: bytes) -> Optional[FrameMeta]:
    """识别帧的长度约定并还原载荷；无法识别返回 None。

    strict:       LEN = len(data) - 8  （LEN 计入类型字节）
    undercounted: LEN = len(data) - 9  （LEN 少算类型字节）
    """
    if len(data) < HEADER_LEN + 1 + 4:
        return None
    len_field = int.from_bytes(data[:HEADER_LEN], "big")
    if len_field >= 1 and len_field == len(data) - HEADER_LEN - 4:
        return FrameMeta(data[HEADER_LEN], bytes(data[HEADER_LEN + 1:-4]),
                         CONVENTION_STRICT)
    if len_field >= 0 and len_field == len(data) - HEADER_LEN - 5:
        return FrameMeta(data[HEADER_LEN], bytes(data[HEADER_LEN + 1:-4]),
                         CONVENTION_UNDERCOUNTED)
    return None


def _remove_node(nodes: List[TLVNode], path: Tuple[int, ...]) -> List[TLVNode]:
    """按路径删除节点（返回新树，不改动原树）。路径为各层下标序列。"""
    idx = path[0]
    out: List[TLVNode] = []
    for i, n in enumerate(nodes):
        if i != idx:
            out.append(n)
            continue
        if len(path) == 1:
            continue  # 删除该节点
        out.append(TLVNode(tag=n.tag, value=n.value,
                           children=_remove_node(n.children or [], path[1:]),
                           offset=n.offset))
    return out


def _all_paths(nodes: List[TLVNode], prefix: Tuple[int, ...] = ()
               ) -> List[Tuple[int, ...]]:
    """树中全部节点路径（先序）。"""
    paths: List[Tuple[int, ...]] = []
    for i, n in enumerate(nodes):
        p = prefix + (i,)
        paths.append(p)
        if n.children:
            paths.extend(_all_paths(n.children, p))
    return paths


class Minimizer:
    """对单个差分用例做保分类化简。classify 使用固定整块喂入以保证确定。"""

    def __init__(self, classify: Optional[Callable[[bytes], Optional[Classification]]] = None):
        self._classify = classify or (lambda b: classify_bytes(b))

    def _preserved(self, candidate: bytes, target: Tuple) -> bool:
        if not candidate:
            return False
        cls = self._classify(candidate)
        return cls is not None and cls.key() == target

    # ---- 三类化简操作 -----------------------------------------------------
    def _try_tlv_deletions(self, cur: bytes, target: Tuple) -> Optional[bytes]:
        meta = frame_meta(cur)
        if meta is None:
            return None
        tree = parse_tlvs_structural(meta.payload)
        if tree is None:
            return None
        for path in _all_paths(tree):
            new_payload = encode_tlvs(_remove_node(tree, path))
            try:
                cand = encode_frame(meta.msg_type, new_payload, meta.convention)
            except ValueError:
                continue
            if len(cand) < len(cur) and self._preserved(cand, target):
                return cand
        return None

    def _try_truncations(self, cur: bytes, target: Tuple) -> Optional[bytes]:
        best: Optional[bytes] = None
        for k in range(len(cur) - 1, 0, -1):
            cand = cur[:k]
            if self._preserved(cand, target):
                best = cand          # 扫描到更短仍保分类的截短
        return best

    def _try_byte_deletions(self, cur: bytes, target: Tuple) -> Optional[bytes]:
        meta = frame_meta(cur)
        if meta is None:
            return None
        for j in range(len(meta.payload)):
            new_payload = meta.payload[:j] + meta.payload[j + 1:]
            try:
                cand = encode_frame(meta.msg_type, new_payload, meta.convention)
            except ValueError:
                continue
            if len(cand) < len(cur) and self._preserved(cand, target):
                return cand
        return None

    # ---- 主循环 -----------------------------------------------------------
    def minimize(self, data: bytes, classification: Classification) -> MinResult:
        target = classification.key()
        if not self._preserved(data, target):
            raise ValueError("原始输入未能复现给定分类，无法最小化")
        cur = data
        reductions: List[str] = []
        iterations = 0
        changed = True
        while changed:
            changed = False
            iterations += 1
            for name, op in (("delete_tlv", self._try_tlv_deletions),
                             ("truncate", self._try_truncations),
                             ("delete_byte", self._try_byte_deletions)):
                cand = op(cur, target)
                if cand is not None and len(cand) < len(cur):
                    reductions.append(f"{name}:{len(cur)}->{len(cand)}")
                    cur = cand
                    changed = True
                    break
        locally_minimal = self.check_local_minimality(cur, target)
        return MinResult(original=data, minimized=cur,
                         classification=target,
                         locally_minimal=locally_minimal,
                         iterations=iterations, reductions=reductions)

    def check_local_minimality(self, data: bytes, target: Tuple) -> bool:
        """局部最小性核查：逐字节删除（含长度/CRC修正）、逐 TLV 删除、
        全部截短均不能复现原分类。"""
        if self._try_byte_deletions(data, target) is not None:
            return False
        if self._try_tlv_deletions(data, target) is not None:
            return False
        if self._try_truncations(data, target) is not None:
            return False
        return True
