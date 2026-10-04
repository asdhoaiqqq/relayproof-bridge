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
- 未参与映射的顶层字段（包括输入自带的 `extra`）各自作为独立成员进入输出事件的
  `extra` 对象，值以原始 JSON 携带；映射不深入未知字段内部，“原样”也不是逐字节
  复制。成员边界、证据值保留语义与完整示例见下文
  [扩展字段 extra：成员边界与证据值保留](#扩展字段-extra成员边界与证据值保留)。
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

### 扩展字段 extra：成员边界与证据值保留

检测规则要把来源日志里的额外字段当作证据读取，因此 `extra` 的边界与“保留”的
含义需要说清楚。

#### 哪些字段进入 extra、哪些不进入

- 只有输入对象的**顶层**标准字段（`timestamp`、`source_ip`、`action`）及其已有
  别名（`time`、`src_ip`、`event_type`）参与映射。其余**顶层**字段彼此独立，各自
  作为一个成员进入输出事件的 `extra`：成员名不变，值是该字段在输入里的整个
  JSON 值（对象、数组、数字、字符串、布尔、`null` 皆可）。
- 映射不进入未知字段内部。未知字段所嵌套的对象里即使出现 `timestamp`、`time`、
  `action`、`event_type`、`source_ip`、`src_ip` 这样的名字，它们也只是来源日志
  的普通内容：不做 RFC3339 校验或时区换算，不做动作去首尾空白，也不与顶层标准
  字段或别名合并。
- 输入本来就含有名为 `extra` 的字段时，它没有任何特殊地位，仍以名为 `extra` 的
  成员放在输出 `extra` 之内（即 `event.extra.extra`）：既不与同级兄弟成员合并，
  也不把它的内层字段提升到输出 `extra`。
- 一个未知字段都没有时，成功事件不输出 `extra`（该成员整体缺省）。

#### “原样保留”到底保留什么

保留针对的是 JSON **值与结构**，不是整段输入逐字节照抄：

- **合法 JSON 数字保留数字类型与原来的数字写法。** 扩展字段里的数字不会经过
  float64 重新解析，因此超出通常浮点精度的整数（如 `9007199254740993`，若走
  float64 会被舍入成 `9007199254740992`）、很长的小数（如
  `1.0000000000000000001`）以及极大/极小指数（如 `1e400`、`1e-400`，float64
  分别会变成 `+Inf` 和 `0`）都以输入的那串字符输出，不会变成舍入后的近似值，也
  不会改写成 `1e+400` 之类的另一种写法。
- **看起来像数字的字符串仍然是字符串。** `"9007199254740993"`、`"1e400"` 输出时
  带引号、类型是字符串，与旁边不带引号的同名数字是两个不同的值；类型不会被
  “纠正”。
- **对象层级、数组元素次序、字符串的实际内容都保持不变**；布尔与 `null` 同样
  照常保留。
- 未知字段内嵌对象里的**重复成员**按其原来的出现次序与各自的值保留（例如
  `{"dup":1,"dup":2}` 原样保留两个成员）。这与**顶层**重复键不同：输入对象
  顶层出现重复成员名会让整行直接失败，重复检测只作用于顶层。
- “原样”**不代表整段输入逐字节复制**：输出会重新序列化，对象与数组内外的结构
  空白会被整理（多余空格/换行被去掉）；输入顶层字段的书写顺序也不决定输出
  `extra` 的成员顺序——输出 `extra` 的成员按成员名排序（内层对象、数组内部的
  次序仍按来源保留）。因此接入方应按成员名读取，而不要依赖顶层书写位置或空白。

#### 例：一条日志同时展示标准规范化与 extra 层级（成功）

下面这条单行日志把关键关系放在一起：`source_ip` 经别名 `src_ip` 提供、时间带非
UTC 时区、动作首尾带空白、IPv6 用等价的冗长写法；未知字段 `nested` 内嵌了名为
`timestamp`/`action`/`time` 的内容、重复成员 `dup`、极端数字与同写法字符串；
另有输入自带的 `extra`，以及普通兄弟字段 `user`。输入里特意写了大量结构空白。

输入（单行）：

```json
{ "timestamp" : "2026-10-04T10:04:05+02:00" , "src_ip" : "0:0:0:0:0:0:0:1" , "action" : " login " , "nested" : { "timestamp" : "not-a-time" , "action" : "  spaced  " , "time" : 123 , "dup" : 1 , "dup" : 2 , "big" : 9007199254740993 , "bigStr" : "9007199254740993" , "huge" : 1e400 , "hugeStr" : "1e400" , "dec" : 1.0000000000000000001 , "tiny" : 1e-400 , "arr" : [9007199254740993 , "9007199254740993" , 1e400 , "1e400" , 1.0000000000000000001 , 1e-400] } , "extra" : { "trace" : "abc" , "big" : 9007199254740993 } , "user" : "alice" }
```

用 `printf '%s\n' '<上面这行>' | ./bin/relayproof normalize` 可直接复现。标准输出
只有行号为 1 的一条成功记录（退出状态 `0`，标准错误为空）：

```json
{"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:04:05Z","source_ip":"::1","action":"login","extra":{"extra":{"trace":"abc","big":9007199254740993},"nested":{"timestamp":"not-a-time","action":"  spaced  ","time":123,"dup":1,"dup":2,"big":9007199254740993,"bigStr":"9007199254740993","huge":1e400,"hugeStr":"1e400","dec":1.0000000000000000001,"tiny":1e-400,"arr":[9007199254740993,"9007199254740993",1e400,"1e400",1.0000000000000000001,1e-400]},"user":"alice"}}}
```

可以据此核对：

- 标准字段照常规范化：`+02:00` 时间换算为 UTC（`10:04:05+02:00` →
  `08:04:05Z`），冗长 IPv6 归一为 `::1`，动作去掉首尾空白成 `login`。
- `nested.timestamp` 仍是字符串 `"not-a-time"`（没有触发任何时间校验或换算），
  `nested.action` 仍带着内部空格 `"  spaced  "`（没有去空白），`nested.time`
  仍是数字 `123`（既不按时间解析，也不与顶层合并）。
- `dup` 的两个重复成员按出现次序都在；`big`/`huge` 等数字保持
  `9007199254740993`、`1e400`、`1.0000000000000000001`、`1e-400` 的原写法和
  数字类型，而 `bigStr`/`hugeStr` 与数组中的同写法值仍是带引号的字符串。
- 输入自带的 `extra` 位于 `event.extra.extra`，未与 `nested`、`user` 合并，内层
  字段也没有被提升出来。
- 结构空白被整理掉；`extra` 的顶层成员按名排序成 `extra`、`nested`、`user`，与
  输入书写顺序无关，而 `nested` 内部与数组内部仍保持来源次序。

读取这类数字证据时，接入方应使用能保留数字字面量的解析方式（如 Go 的
`json.Decoder` 配合 `UseNumber()`）；若直接解析成 `float64`/`any`，
`9007199254740993` 会被读成 `9007199254740992`、`1e400` 会溢出为 `+Inf`，那是
读取方造成的精度损失，规范化输出本身并未近似。

#### 例：把标准动作字段改成数字（失败）

数字保留只适用于扩展数据。把上例唯一一处标准字段——`action`——的值从字符串
`" login "` 改成数字 `42`，其余完全不动：

```json
{ "timestamp" : "2026-10-04T10:04:05+02:00" , "src_ip" : "0:0:0:0:0:0:0:1" , "action" : 42 , "nested" : { "timestamp" : "not-a-time" , "action" : "  spaced  " , "time" : 123 , "dup" : 1 , "dup" : 2 , "big" : 9007199254740993 , "bigStr" : "9007199254740993" , "huge" : 1e400 , "hugeStr" : "1e400" , "dec" : 1.0000000000000000001 , "tiny" : 1e-400 , "arr" : [9007199254740993 , "9007199254740993" , 1e400 , "1e400" , 1.0000000000000000001 , 1e-400] } , "extra" : { "trace" : "abc" , "big" : 9007199254740993 } , "user" : "alice" }
```

它仍是字段类型错误，而不是“数字也能当动作”：标准输出只有行号为 1 的失败原因，
不带 `event`，`nested` 等证据不会被部分写出。退出状态为 `1`，标准错误为空
（逐行原因只在标准输出记录的 `error` 里）：

```json
{"line":1,"ok":false,"error":"field \"action\": value must be a string, got number"}
```

这与[多处错误的报告顺序](#多处错误的报告顺序)及[标准输出、标准错误与退出状态
](#标准输出标准错误与退出状态)一节一致：`1` 表示输入输出正常结束但存在非法
日志行，`2` 才是输入输出本身中断；失败原因始终只落在该记录的 `error` 字段。

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
