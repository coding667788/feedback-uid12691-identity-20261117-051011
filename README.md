# 结构化消息解析器的差分模糊测试与最小化工作台

完全离线的差分测试工作台：用**严格解析器**对比**带三处明确缺陷的教学解析器**，
通过确定性生成器发现差分，再做保分类最小化。仅使用 Python 3.12 标准库，
Windows / 仅 CPU，无 Docker、无外部服务，所有操作局限在项目目录内。

## 协议定义（仅用于本题）

```
帧   = LEN(4字节大端) || TYPE(1字节) || TLV载荷 || CRC32(4字节大端)
TLV  = TAG(1字节) || TLEN(2字节大端) || VALUE(TLEN字节)
```

- `LEN` 计入 TYPE 与 TLV 载荷，**不含**自身与 CRC；`CRC32`（zlib 语义）覆盖 TYPE 与载荷。
- `TAG=0x20` 表示嵌套 TLV（VALUE 本身是 TLV 序列）；顶层 TLV 深度为 0，**最多 8 层**
  （深度 0..8 合法，深度 9 报错 `DEPTH_EXCEEDED`）。
- `TAG=0x01` 为关键标签，**同一层最多出现一次**（重复报错 `DUPLICATE_TAG`）。
- 其余未知标签作为**不透明值**保留在解析树中。
- 单帧最大 **64KiB = 65536 字节**（含 4 字节 LEN 与 4 字节 CRC，即 LEN ≤ 65528）。
- 解析器**逐字节增量**工作（`feed` 任意分块），所有错误位置都是**原始流绝对偏移**。

## 三处教学缺陷

严格解析器 `StrictParser` 与教学解析器 `TeachingParser` 共享同一状态机核心
（`solution/parsers.py`），教学解析器通过三个显式开关引入缺陷：

| # | 缺陷 | 开关 | 行为 |
|---|------|------|------|
| 1 | 长度少算一字节 | `LENGTH_RETRY=True` | 严格定界下 CRC 失败时，按“发送方少算了类型字节（LEN 只计载荷）”重试：载荷按 LEN 字节解释、CRC 顺延 1 字节，重试校验通过即**接受** |
| 2 | 重复关键标签接受 | `CHECK_DUPLICATE_KEY=False` | 同一层重复 0x01 不再报错 |
| 3 | 嵌套深度多接受一层 | `MAX_DEPTH=9` | 深度 9 的 TLV 也被接受 |

三个缺陷都是“教学解析器接受了严格解析器拒绝的输入”，因此**合法帧上两者行为
完全一致**（有测试保证），差分只出现在违约输入上。

## 差分判定

对每个用例，同一输入分别喂给两个解析器（相同分块），比较结论：

- **接受状态**：`accept` / `reject(错误码)` / `incomplete`
- **消费边界**：已接受帧数 + 已消费字节数

仅当两者结论不同才归为**差分**；任一解析器抛出未捕获异常记为
`internal_error`，**单独计数、绝不算发现**。差分分类：

| 分类 | 含义 |
|------|------|
| `length_undercount` | 严格拒绝（CRC/长度类）而教学接受 → 缺陷1 |
| `duplicate_key_tag` | 严格 `DUPLICATE_TAG` 而教学接受 → 缺陷2 |
| `nesting_depth` | 严格 `DEPTH_EXCEEDED` 而教学接受 → 缺陷3 |
| `consumed_mismatch` | 接受状态一致但消费边界不同 |
| `other` | 其他接受状态差异 |

## 生成器

`CaseGenerator(seed)` 的第 i 个用例只取决于 `(seed, i)`（子种子 =
`sha256(f"{seed}:{i}")`），因此**进程中断后从断点恢复不会改变同一种子的生成
序列**。用例混合：40% 保持结构的变异（改类型字节/不透明值/追加未知标签，
产物仍严格合法，作阴性对照），三种破坏单一约束的变异各 20%：

- `break_length`：LEN = len(payload)（少算类型字节），CRC 仍覆盖 TYPE||payload
- `break_dup`：同一层插入第二个 0x01（长度与 CRC 均正确）
- `break_depth`：用 0x20 包裹使最深 TLV 恰好落在深度 9

## 最小化

`Minimizer` 在**保留原差分分类**（分类键完全相等）的前提下循环化简至不动点：

1. **截短**：删除尾部字节（原始截短）；
2. **删除 TLV**：结构解析后删除任一 TLV 节点，重算祖先嵌套长度、帧长度字段
   （保持原长度约定 strict/undercounted）与 CRC32；
3. **单字节删除**：删除载荷区任一字节后同样调整长度与校验和。

每个候选都重新跑双解析器验证分类。不动点后再做**局部最小性核查**：逐字节
删除（含修正）、逐 TLV 删除、全部截短均不能复现原分类，结果写入
`locally_minimal`。分类键采用归一化签名（接受状态、错误码、帧数、是否消费
全部输入、两侧消费边界是否一致），与输入尺寸无关。

## 使用

```bash
# 主入口：按 cases.json 运行，写出 result.json
python -m solution --input cases.json --output result.json

# 重放单个 finding（finding 文件中保存的重放命令即此形式）
python -m solution --replay findings/finding-000001-duplicate_key_tag.json

# 重新生成样例二进制
python -m solution --make-samples --output-dir samples

# 自动化测试
python -m unittest discover -s tests -v
```

### cases.json schema

相对路径相对 cases.json 所在目录解析。

```json
{"mode": "fuzz",
 "seed": 12691,            // 整数种子（必填）
 "cases": 300,             // 本批用例数（必填，正整数）
 "findings_dir": "findings", // findings 输出目录（默认 findings）
 "minimize": true,         // 是否最小化（默认 true）
 "resume": false,          // true 时从 findings_dir/state.json 的 next_index 继续
 "start_index": 0}         // 显式起始序号（resume 优先）
```

```json
{"mode": "parse", "parser": "strict",      // 或 "teaching"
 "input_file": "samples/dup_tag.bin",      // 可引用项目内任意源文件/二进制样例
 "chunk_sizes": [1, 3, 2]}                 // 可选分块；缺省整块喂入
```

```json
{"mode": "replay", "finding_file": "findings/finding-000001-duplicate_key_tag.json"}
```

### result.json schema（fuzz 模式）

```json
{"status": "ok", "mode": "fuzz", "seed": 12691, "start_index": 0,
 "cases_run": 300, "clean": 128, "internal_errors": 0,
 "differentials": {"total": 172,
   "by_category": {"length_undercount": 47, "duplicate_key_tag": 52,
                   "nesting_depth": 73}},
 "findings": [{"id": "...", "category": "...", "case_index": 1,
               "file": "finding-000001-duplicate_key_tag.json",
               "original_size": 56, "minimized_size": 19,
               "locally_minimal": true}],
 "state_file": "findings/state.json", "errors": []}
```

### finding 文件（findings/finding-NNNNNN-category.json）

保存**种子、用例序号、原样字节(hex)、差分分类、最小化结果、重放命令**：

```json
{"id": "seed12691-000001-duplicate_key_tag", "seed": 12691, "case_index": 1,
 "case_kind": "break_dup", "category": "duplicate_key_tag",
 "classification": {"strict": ["reject", "DUPLICATE_TAG", 0, false],
                    "teaching": ["accept", null, 1, true],
                    "consumed_equal": false},
 "original_hex": "...", "original_size": 56,
 "minimized_hex": "...", "minimized_size": 19, "locally_minimal": true,
 "reductions": ["delete_tlv:56->52", "..."],
 "replay_command": "python -m solution --replay findings/finding-000001-....json"}
```

`findings/state.json` 记录 `{"seed", "next_index"}` 供断点恢复。

### 错误码与退出码

| 退出码 | 错误码 | 含义 |
|--------|--------|------|
| 0 | — | 成功（发现差分也是成功） |
| 2 | `E_SCHEMA` | cases.json 缺失字段/类型错误/非法 JSON |
| 2 | `E_INPUT` | 引用的输入文件不存在或不可读 |
| 2 | `E_REPLAY` | finding 文件非法 |
| 1 | `E_INTERNAL` | 未捕获内部错误（不会裸抛异常） |

解析层错误码：`LENGTH_INVALID`、`FRAME_TOO_LARGE`、`CRC_MISMATCH`、
`TLV_TRUNCATED`、`DEPTH_EXCEEDED`、`DUPLICATE_TAG`。

## 目录结构

```
solution/            源代码包
  protocol.py        协议常量、CRC、帧/TLV 编解码、结构解析
  parsers.py         增量状态机 + 严格/教学解析器（三个缺陷开关）
  generator.py       确定性用例生成器（断点恢复安全）
  differ.py          差分运行与分类
  minimizer.py       保分类最小化 + 局部最小性核查
  workbench.py       fuzz 编排、findings 持久化、恢复、重放
  sampledata.py      项目内样例数据构造（确定性）
  __main__.py        CLI 入口与 cases.json 调度
samples/             样例二进制（合法/嵌套/三类缺陷/坏CRC/截短/多帧）
tests/               unittest 测试（40 例）
cases.json           示例输入（fuzz 模式，种子 12691）
```

## 验收场景对应

- **固定种子稳定发现三类缺陷**：`tests/test_differential.py` 固定种子 12691、
  60 用例，断言三类缺陷精确计数（11/9/19）且重跑逐字段一致。
- **最小化结果逐字节删除检查局部最小性**：`tests/test_minimizer.py` 对三类
  缺陷分别断言分类保留、尺寸缩小、`locally_minimal=True`，并独立逐字节
  删除复核。
- **任意分块方式不得改变严格解析结论**：`tests/test_strict_parser.py` 对 8
  个样例语料 × （整块/逐字节/2/3/7/三组确定性随机分块）断言结论与错误
  偏移完全一致。
- **断点恢复不改变生成序列**：`tests/test_generator.py`（生成器级）与
  `tests/test_cli.py`（CLI resume 与不中断运行 findings 完全一致）。
