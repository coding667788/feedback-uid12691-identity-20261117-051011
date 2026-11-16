"""确定性用例生成器。

同一 seed 的生成序列与进程、断点恢复无关：第 i 个用例的字节仅取决于
(seed, i) —— 每个用例使用由 sha256(f"{seed}:{i}") 派生的独立随机源，
因此进程中断后从任意位置恢复都不会改变同一种子的生成序列。

两类变异：
- 保持结构的变异（structure）：保持 TLV 树结构合法，仅改动类型字节、
  不透明值、追加未知标签等，产物仍是严格合法帧（用作阴性对照）。
- 破坏单一约束的变异（break_*）：恰好破坏一条约束，分别对准三处教学缺陷：
    break_length -> LEN 少算一字节（LEN = len(payload)，CRC 仍覆盖 TYPE||payload）
    break_dup    -> 同一层重复关键标签 0x01
    break_depth  -> 嵌套深度达到 9（超出严格的 8 层）
"""
from __future__ import annotations

import hashlib
import random
from typing import List, Tuple

from .protocol import (
    CONVENTION_STRICT,
    CONVENTION_UNDERCOUNTED,
    TAG_KEY,
    TAG_NESTED,
    TLVNode,
    encode_frame,
    encode_tlv,
    encode_tlvs,
    tree_max_depth,
)

KIND_STRUCTURE = "structure"
KIND_BREAK_LENGTH = "break_length"
KIND_BREAK_DUP = "break_dup"
KIND_BREAK_DEPTH = "break_depth"

# 用例类型混合比例：40% 保持结构，三种破坏各 20%
_MIX = ((0.40, KIND_STRUCTURE), (0.60, KIND_BREAK_LENGTH),
        (0.80, KIND_BREAK_DUP), (1.00, KIND_BREAK_DEPTH))

_OPAQUE_TAGS = (0x02, 0x03, 0x7F, 0x80, 0xFF)   # 未知标签按不透明值保留


def derive_case_seed(seed: int, index: int) -> int:
    """由 (seed, index) 派生确定性子种子。"""
    digest = hashlib.sha256(f"{seed}:{index}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _random_value(rng: random.Random) -> bytes:
    return bytes(rng.randrange(256) for _ in range(rng.randint(0, 6)))


def _random_tlvs(rng: random.Random, depth: int, max_base_depth: int = 2
                 ) -> List[TLVNode]:
    """生成随机 TLV 树（合法：0x01 同层唯一，深度不超过 max_base_depth）。"""
    count = rng.randint(1, 3)
    nodes: List[TLVNode] = []
    used_key = False
    for _ in range(count):
        choices = list(_OPAQUE_TAGS)
        if not used_key:
            choices.append(TAG_KEY)
        if depth < max_base_depth:
            choices.append(TAG_NESTED)
        tag = rng.choice(choices)
        if tag == TAG_KEY:
            used_key = True
            nodes.append(TLVNode(tag=tag, value=_random_value(rng)))
        elif tag == TAG_NESTED:
            nodes.append(TLVNode(tag=tag, value=b"",
                                 children=_random_tlvs(rng, depth + 1,
                                                       max_base_depth)))
        else:
            nodes.append(TLVNode(tag=tag, value=_random_value(rng)))
    return nodes


def _mutate_values(rng: random.Random, nodes: List[TLVNode]) -> None:
    """保持结构的就地变异：翻转不透明值的个别字节。"""
    for n in nodes:
        if n.children is not None:
            _mutate_values(rng, n.children)
        elif n.value and rng.random() < 0.4:
            buf = bytearray(n.value)
            buf[rng.randrange(len(buf))] ^= 0xFF
            n.value = bytes(buf)


class CaseGenerator:
    """确定性用例生成器。case(i) 只依赖 (seed, i)，可断点恢复。"""

    def __init__(self, seed: int):
        self.seed = seed

    def case(self, index: int) -> Tuple[bytes, str]:
        """返回 (用例字节, 用例类型)。"""
        rng = random.Random(derive_case_seed(self.seed, index))
        msg_type = rng.randrange(256)
        tree = _random_tlvs(rng, 0)
        payload = encode_tlvs(tree)

        r = rng.random()
        kind = KIND_STRUCTURE
        for threshold, k in _MIX:
            if r < threshold:
                kind = k
                break

        if kind == KIND_STRUCTURE:
            _mutate_values(rng, tree)
            if rng.random() < 0.5:
                # 追加一个未知标签 TLV（仍为合法结构）
                tree.append(TLVNode(tag=rng.choice(_OPAQUE_TAGS),
                                    value=_random_value(rng)))
            new_type = rng.randrange(256)
            return encode_frame(new_type, encode_tlvs(tree),
                                CONVENTION_STRICT), kind

        if kind == KIND_BREAK_LENGTH:
            # LEN 少算一字节：LEN = len(payload)（未计入类型字节），
            # CRC 仍覆盖 TYPE||payload —— 严格解析器定界错位拒绝，
            # 教学解析器经缺陷1重试接受。
            return encode_frame(msg_type, payload,
                                CONVENTION_UNDERCOUNTED), kind

        if kind == KIND_BREAK_DUP:
            # 同一层重复关键标签 0x01（长度与 CRC 均正确）
            if not any(n.tag == TAG_KEY for n in tree):
                tree.insert(0, TLVNode(tag=TAG_KEY, value=b"k"))
            tree.append(TLVNode(tag=TAG_KEY, value=b"dup"))
            return encode_frame(msg_type, encode_tlvs(tree),
                                CONVENTION_STRICT), kind

        if kind == KIND_BREAK_DEPTH:
            # 用 0x20 包裹原载荷，使最深 TLV 恰好落在深度 9（超出严格的 8，
            # 但不超过教学解析器的 9）
            base_depth = tree_max_depth(tree)
            wrapped = payload
            for _ in range(9 - base_depth):
                wrapped = encode_tlv(TAG_NESTED, wrapped)
            return encode_frame(msg_type, wrapped, CONVENTION_STRICT), kind

        raise AssertionError(f"unreachable kind {kind}")
