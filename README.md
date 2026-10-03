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
- 字符完整性在 JSON 解析之前对整条原始日志检查：原始字节必须是合法 UTF-8；
  JSON 字符串（字段名与任意深度的字符串值，含未知字段的嵌套对象、数组与输入
  自带的 `extra`）里的 `\uXXXX` 转义若为高代理项（D800–DBFF），后面必须紧接
  低代理项（DC00–DFFF）转义，单独出现的低代理项同样非法。命中任一问题整条日志
  失败，绝不把损坏字符替换成“�”后再做字段映射、别名比较或存入 extra，也不通过
  删除字节、补齐转义或替换字符来修复。合法中文、表情、正确配对的代理项转义以及
  用户明确输入的合法“�”字符照常可用；`\\` 转义后的 `uD800` 只是普通文本，原样保留。

### 多处错误的报告顺序

一条日志可能同时带有错误时间、非法地址、空动作等多个问题，但每条失败记录只有
一个 `error`、不携带 `event`，因此规范化按固定顺序只报告首先遇到的那一个。对于
**已经通过字符完整性检查、并成功解析为 JSON 对象**的日志，顺序如下：

1. 先检查所有“已提供”的映射字段，固定按 `timestamp`、`source_ip`、`action` 的
   标准字段顺序进行，与成员在输入对象中的书写位置无关。用标准名还是别名
   （`time`、`src_ip`、`event_type`）提供都归入对应标准字段，原因中的字段名也
   始终使用标准名。同一字段的标准名与别名都会被校验：任一取值不合法就按该字段
   失败；都合法但规范化后不一致，则按别名冲突失败。一旦在该顺序中遇到第一个不
   合法的字段，立即结束，本轮不再检查后面的字段。
2. 只有已提供的映射字段全部合法、且没有别名冲突后，才检查必填字段是否缺失。
   `timestamp` 与 `action` 必填；两者都缺失时，先报告 `missing required field
   "timestamp"`。
3. 显式给出的 `null` 属于“已提供但类型错误”，在第 1 步就失败，**不能按缺省
   处理**留到第 2 步；对象、数组、布尔、数字等非字符串类型同理。例如动作以
   `null` 给出时报告 `field "action": value must be a string, got null`，字段名
   用的是标准名 `action` 而不是别名 `event_type`。

因此一次失败只揭示沿上述顺序首先遇到的问题；把它改正后再次规范化，才可能看到
下一个字段的错误。

这一顺序有明确前提：字符损坏、JSON 语法不合法、非对象输入或重复顶层键会在映射
字段检查**之前**就让整行失败，此时的原因与字段顺序无关，不能据此推断字段检查的
先后。这类结果同样只有一条带原始物理行号的 `ok:false` 记录：只有一个 `error`、
没有 `event`。

#### 例：三个映射字段都有问题，逐步修正同一条日志

下面每一步都是把同一条日志改正一处后、作为**唯一一行**输入喂给
`./bin/relayproof normalize`（可用 `printf '%s\n' '<JSON>' | ./bin/relayproof
normalize` 逐行复现），所以行号始终是 1。

第 1 步：时间（小时 25）、地址（`999.1.2.3`）、动作（纯空白）都不合法，但只报告
排在最前的时间错误（退出状态 `1`）。

输入：

```json
{"timestamp":"2026-10-04T25:00:00Z","source_ip":"999.1.2.3","action":"   "}
```

输出：

```json
{"line":1,"ok":false,"error":"field \"timestamp\": invalid RFC3339 timestamp: hour 25 out of range (00-23)"}
```

第 2 步：仅把时间改成合法值，地址与空动作的问题依旧存在，这时才看到地址错误
（退出状态 `1`）。

输入：

```json
{"timestamp":"2026-10-04T08:30:00Z","source_ip":"999.1.2.3","action":"   "}
```

输出：

```json
{"line":1,"ok":false,"error":"field \"source_ip\": invalid IP address \"999.1.2.3\" (no port allowed)"}
```

第 3 步：再把地址改成合法 IPv6，只剩空动作，于是报告动作错误（退出状态 `1`）。

输入：

```json
{"timestamp":"2026-10-04T08:30:00Z","source_ip":"2001:db8::1","action":"   "}
```

输出：

```json
{"line":1,"ok":false,"error":"field \"action\": action must not be empty"}
```

第 4 步：把动作改成非空字符串，三个字段全部合法，得到成功事件（退出状态 `0`）。

输入：

```json
{"timestamp":"2026-10-04T08:30:00Z","source_ip":"2001:db8::1","action":"login"}
```

输出：

```json
{"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","source_ip":"2001:db8::1","action":"login"}}
```

可见改正一个问题后仍可能失败：每次只揭开顺序中的下一个问题，而不是一次性列出
全部错误。

#### 例：缺少 timestamp，但 event_type 为 null

这条日志没有 `timestamp`/`time`，动作经别名 `event_type` 显式给出，值为 `null`。
因为 `null` 是“已提供但类型错误”，第 1 步的字段类型检查先命中 `action`，此时还
轮不到第 2 步的必填检查，所以不会先报缺少时间（退出状态 `1`）。

输入：

```json
{"src_ip":"10.0.0.1","event_type":null}
```

输出：

```json
{"line":1,"ok":false,"error":"field \"action\": value must be a string, got null"}
```

把动作改成合法字符串后，已提供字段全部合法，才进入必填检查并报告缺少
`timestamp`（退出状态仍为 `1`）。

输入：

```json
{"src_ip":"10.0.0.1","event_type":"login"}
```

输出：

```json
{"line":1,"ok":false,"error":"missing required field \"timestamp\""}
```

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
