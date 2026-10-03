# 跨链消息与轻客户端验证服务

## 用途

轻客户端头同步、消息封装与投递、重放防护、中继重试与超时、储备与状态证明校验、跨链可观测。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `relayproof/`，命令入口位于 `cmd/relayproof/`。

```bash
go run ./cmd/relayproof demo
go run ./cmd/relayproof version
go test ./...
```

## 离线日志规范化

检测规则需要统一读取不同来源的日志，`normalize` 子命令从标准输入逐行读取 JSON，
在标准输出逐行给出规范化结果，全部行为可离线、确定性复现：

```bash
go run ./cmd/relayproof normalize < logs.jsonl
```

### 字段与输出规则

- 标准事件字段为 `timestamp`、`source_ip`、`action`，分别接受别名
  `time`、`src_ip`、`event_type`；`timestamp` 与 `action` 必填，`source_ip` 可缺省。
- `timestamp` 只接受严格 RFC3339 字符串：年月日与时分秒均为两位数字，必须带
  时区（`Z` 或 `±HH:MM`，偏移小时 00-23、分钟 00-59）；小数秒可缺省，存在时
  必须以点号引导一到九位数字，不接受逗号、补位、截断或进位。换算到 UTC 后的
  年份必须落在 0000-9999（含端点），否则即使输入本身合法也整条失败——成功事件
  只能使用四位无符号年份表示的 RFC3339Nano 时间。统一转成 UTC 并以
  RFC3339Nano 输出（保留实际精度、去掉小数尾零）；`action` 为去首尾空白后的非空字符串；`source_ip` 必须是
  不带端口的合法 IPv4/IPv6，同一地址的不同写法输出相同结果。
- 标准名与别名同时出现时分别规范化后比较：一致则合并，不一致则整条失败；
  `null` 或类型不符按失败处理，重复顶层键同样失败。
- 未参与映射的字段（包括输入自带的 `extra`）原样保留在输出事件的 `extra` 对象中。
- 每个非空白物理行在标准输出对应一条结果：成功为
  `{"line":行号,"ok":true,"event":...}`，失败为
  `{"line":行号,"ok":false,"error":"原因"}`；空白行不产生输出但计入行号。
  存在失败行时继续处理后续日志。

### 标准输出、标准错误与退出状态

规范化结果只走标准输出，运行诊断只走标准错误，两者分工明确：

- **标准输出**：每个非空白物理行一条 JSON，严格按输入顺序排列。失败记录带有
  该行的**原始物理行号**和失败 `error` 原因，但**不带 `event` 字段**；它表示
  “这一条日志无效”，不表示命令运行出错。
- **标准错误**：不重复打印任何逐行失败原因（逐行原因只在标准输出的 `error`
  字段里）。只有输入读取或结果写出本身发生故障时，才输出一行以 `normalize: `
  开头的诊断。
- **退出状态**：

  | 状态 | 含义 |
  | --- | --- |
  | `0` | 输入正常结束，且所有非空白日志行都合法 |
  | `1` | 输入读取与结果写出都正常结束，但有一条或多条日志行规范化失败 |
  | `2` | 输入读取或结果写出发生故障，处理已停止；标准错误有 `normalize: ` 诊断 |

  因此看到 `ok:false` 记录但退出 `1`、标准错误为空，可以判定只是个别日志
  无效；看到退出 `2` 且标准错误有诊断，则是本次输入输出中断，标准输出可能
  不完整，不能再按“每个非空白行都有一条结果”来解读。

### 可照用的离线示例

准备一个包含合法日志、字段无效日志、空白行和后续合法日志的文件：

```bash
cat > logs.jsonl <<'EOF'
{"timestamp":"2026-10-04T08:30:00Z","src_ip":"2001:DB8::1","action":"login"}
{"timestamp":"2026-10-04T08:31:00Z","action":42}

{"time":"2026-10-04T10:00:00+02:00","event_type":"withdraw","src_ip":"10.0.0.1","trace_id":"abc-1"}
EOF
go run ./cmd/relayproof normalize < logs.jsonl
echo "exit=$?"
```

标准输出逐行为：

```json
{"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","source_ip":"2001:db8::1","action":"login"}}
{"line":2,"ok":false,"error":"field \"action\": value must be a string, got number"}
{"line":4,"ok":true,"event":{"timestamp":"2026-10-04T08:00:00Z","source_ip":"10.0.0.1","action":"withdraw","extra":{"trace_id":"abc-1"}}}
```

标准错误为空，`echo "exit=$?"` 打印 `exit=1`。从中可以看出：

- 第 1 行合法：别名 `src_ip` 并入 `source_ip`，IPv6 输出为同一地址的规范写法。
- 第 2 行失败：`action` 是数字而不是字符串；记录带原始物理行号 `2` 和原因，
  不带 `event`。该行失败**不会阻止**后续日志处理。
- 第 3 行是空白行：**没有任何输出，但仍占用一个物理行号**，所以末条记录的
  行号是 `4` 而不是 `3`。
- 第 4 行合法：别名 `time`、`event_type` 并入标准字段，`+02:00` 换算为 UTC，
  未参与映射的 `trace_id` 原样收进 `extra`。

全部日志行都合法时，标准输出只有 `ok:true` 记录，标准错误为空，退出 `0`：

```bash
printf '%s\n' \
  '{"timestamp":"2026-10-04T08:30:00Z","action":"login"}' \
  '{"time":"2026-10-04T10:00:00+02:00","event_type":"withdraw","src_ip":"10.0.0.1"}' \
  | go run ./cmd/relayproof normalize
# 两条 ok:true 记录，标准错误为空，退出状态 0
```

### 文件结束与输入输出中断

- **正常文件结束**：读到 EOF 不是故障。即使末行没有结尾换行符，它仍是一次
  完整读到的内容，会照常规范化并输出，然后以退出 `0` 或 `1` 结束。
- **读取中断**：若读取在一行中途故障（返回的不是 EOF），随故障一起拿到的
  未结束片段属于这次失败读取的一部分，不是一条完整日志行：它**没有逐行
  结果，也不计入失败行数**。此前已经完整读到的日志仍按原顺序处理并输出，
  随后处理停止，命令以退出 `2` 结束。
- **写出中断**：写出故障会立即停止处理，标准输出上可能已经留下一条写了
  一半的末条 JSON。本工具**不保证中断后的输出仍然完整或可逐行解析**；
  失败行数也不能解释成“还有多少条结果没写出去”。
- **读取已失败、收尾写出又失败**：读故障仍是主要原因——错误仍能被
  `errors.Is(err, ErrLogRead)` 命中，并保留原始读取原因；后来的写故障只把
  自己的文字追加进同一条错误信息，不会掩盖读故障。对应到命令入口，仍是
  退出 `2`，标准错误那一行 `normalize: ...` 诊断中会同时出现两段描述。

### 在 Go 代码中接入：NormalizeReader

公共入口 `relayproof.NormalizeReader(r io.Reader, w io.Writer) (failures int, err error)`
与命令行跑的是同一套逻辑：

```go
import (
	"errors"
	"fmt"
	"io"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

func normalizeLogs(r io.Reader, w io.Writer) (invalidLines int, err error) {
	failures, err := relayproof.NormalizeReader(r, w)
	if err != nil {
		switch {
		case errors.Is(err, relayproof.ErrLogRead):
			return failures, fmt.Errorf("日志读取中断: %w", err)
		case errors.Is(err, relayproof.ErrLogWrite):
			return failures, fmt.Errorf("结果写出中断: %w", err)
		default:
			return failures, err
		}
	}
	return failures, nil
}
```

两个返回值的含义：

- `failures` 是**已经完整处理的非空白行中规范化失败的行数**。遇到无效日志时
  它加一，而 `err` 为空——无效日志是逐行数据结果（对应写出的 `ok:false`
  记录），不是运行故障。
- `err` 只在输入读取或结果写出发生故障时非空，并立即停止处理：读故障包装
  `ErrLogRead`，写故障包装 `ErrLogWrite`，调用方用 `errors.Is` 区分两类故障，
  并能继续沿包装链识别原始原因（如底层文件系统错误）。
- `failures` 只反映已经处理过的无效日志：它**不是未成功写出的结果数量**
  （写出经过缓冲，已处理的结果也可能尚未到达底层写入端），也**不能用
  `failures == 0` 代替输入输出成功**——流是否正常结束只看 `err` 是否为空。
  读取故障附带的未结束片段同样不产生结果、不计入 `failures`。
- 映射到命令入口：`err == nil && failures == 0` 对应退出 `0`；
  `err == nil && failures > 0` 对应退出 `1`；`err != nil` 对应退出 `2`，
  并在标准错误输出 `normalize: <err>`。


## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
