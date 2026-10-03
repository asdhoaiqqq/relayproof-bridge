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

### 字段规则

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

### 标准输出、标准错误与退出状态

每条非空白物理行在**标准输出**产生一条 JSON 记录：

- 成功：`{"line":行号,"ok":true,"event":...}`，`event` 为规范化后的事件；
- 失败：`{"line":行号,"ok":false,"error":"原因"}`，带原始物理行号与原因，
  不带 `event` 字段。某行失败不会阻止后续日志处理，后续行仍按原顺序输出。
- 空白行不产生任何输出，但仍占用一个物理行号。

**标准错误**只用于流级诊断，不会逐行重复失败原因——每行失败的具体原因只出现在
标准输出对应记录的 `error` 字段里。仅有日志行失败、输入输出正常结束时，标准错误
没有任何内容。

退出状态把三种结局区分开：

| 退出状态 | 含义 |
|---|---|
| `0` | 输入正常结束，全部日志行合法 |
| `1` | 输入输出正常结束，但有一条或多条日志行规范化失败（失败数见标准输出中 `ok:false` 的记录） |
| `2` | 输入读取或结果写出发生故障而中断；标准错误打印一行以 `normalize:` 开头的诊断，此时不能再用退出状态判断日志本身是否合法 |

因此批量规范化后应先看退出状态：`1` 只是其中几条日志无效，`2` 才表示本次
输入输出已经中断。

### 离线示例

先构建一次二进制（`go run` 在子命令非零退出时会额外打印 `exit status 1`，
构建后可直接观察程序自身的退出状态）：

```bash
mkdir -p bin
go build -o bin/relayproof ./cmd/relayproof
./bin/relayproof normalize <<'EOF'
{"timestamp":"2026-10-04T08:30:00Z","action":"login","src_ip":"2001:db8::1","user":"alice"}
{"timestamp":"2026-10-04T25:00:00Z","action":"login"}

{"time":"2026-10-04T09:00:00+02:00","event_type":" transfer ","src_ip":"10.0.0.1"}
EOF
echo "exit=$?"
```

标准输出逐行为（第 3 行为空白行，无输出但仍占用行号，所以最后一条记录是 `line:4`）：

```json
{"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","source_ip":"2001:db8::1","action":"login","extra":{"user":"alice"}}}
{"line":2,"ok":false,"error":"field \"timestamp\": invalid RFC3339 timestamp: hour 25 out of range (00-23)"}
{"line":4,"ok":true,"event":{"timestamp":"2026-10-04T07:00:00Z","source_ip":"10.0.0.1","action":"transfer"}}
```

标准错误为空，退出状态为 `exit=1`：第 2 行无效，但第 4 行仍被正常处理。
若把第 2 行也换成合法日志，则标准错误同样为空、退出状态为 `0`。

### 在 Go 代码中通过 NormalizeReader 接入

同一功能的公共入口是
`relayproof.NormalizeReader(r io.Reader, w io.Writer) (failures int, err error)`，
命令行的 `normalize` 子命令就是对它的薄封装：

```go
import (
    "errors"
    "fmt"
    "io"

    "github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

func normalizeLogs(r io.Reader, w io.Writer) error {
    failures, err := relayproof.NormalizeReader(r, w)
    switch {
    case errors.Is(err, relayproof.ErrLogRead):
        return fmt.Errorf("读取日志中断（此前有 %d 条无效日志）: %w", failures, err)
    case errors.Is(err, relayproof.ErrLogWrite):
        return fmt.Errorf("写出结果中断（此前有 %d 条无效日志）: %w", failures, err)
    case err != nil:
        return err
    }
    if failures > 0 {
        fmt.Printf("输入输出正常结束，其中 %d 条日志无效\n", failures)
    }
    return nil
}
```

两个返回值含义不同，必须分开判断：

- `failures` 是**已经处理的完整行中规范化失败的行数**。遇到无效日志时只增加
  `failures`，返回的 `err` 仍为 `nil`，处理继续。
- `err` 只表示流级故障（输入读取或结果写出）。故障会立即停止处理，返回错误
  分别包着哨兵 `ErrLogRead`、`ErrLogWrite`，用 `errors.Is` 区分；错误链中同时
  保留底层原始原因，继续 `errors.Is` 即可识别（例如上游 reader 返回的具体错误）。
- `failures` 不是“未能成功写出的结果数量”，也不能用 `failures == 0` 代替
  输入输出成功：流在第一条日志之前就故障时 `failures` 同样为零，但 `err` 非空。
  对应到命令入口，这类可捕获的输入输出故障一律以退出 `2` 结束，并在标准错误
  给出以 `normalize:` 开头的诊断。

正常文件结束与读取中断的区别：

- 读到干净的 EOF 不是错误，即使末行没有换行符，该末行也会照常处理并计入行号。
- 读取故障时，随故障一起返回的未结束片段属于这次失败读取的一部分，不是完整
  日志行：它既不产生逐行结果，也不计入 `failures`；此前已经读到的完整日志仍按
  原顺序处理并计数行号。
- 写出故障时处理立即停止，输出端可能残留一条写了一半的末条 JSON；文档不保证
  中断之后仍有完整输出，调用方不应继续在该 writer 上追加内容。
- 若读取已经失败、收尾刷新写出时又失败：读故障仍是主要原因
  （`errors.Is(err, ErrLogRead)` 成立、底层读取原因也仍在错误链中），后来的
  写故障只体现在返回错误的文字里，命令入口同样按退出 `2` 报告。


## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
