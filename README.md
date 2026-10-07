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
  失败原因中的 `at byte offset N` 以什么为起点、两类损坏各指向哪个字节，以及一行
  同时存在两种损坏时为什么报告的是这一处，见下文
  [字符损坏的字节位置：从失败记录找回原始字节](#字符损坏的字节位置从失败记录找回原始字节)。

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

### 字符损坏的字节位置：从失败记录找回原始字节

字符完整性失败时，记录的 `error` 除了原因，还带一个形如 `at byte offset N` 的
位置。下面交代这个 N 以什么为起点、非法 UTF-8 与未配对代理项转义各自指向哪个
字节，以及一行同时存在两种损坏时为什么报告的是这一处。结论都可用本节给出的命令
离线复现。

#### N 从哪里数、按什么计数

- **N 从零开始。** 第一条字节是 0，不是 1。
- **针对“该行去掉首尾合法 JSON 空白后的内容”计算。** 规范化在检查字符完整性
  之前，只裁掉该行文档首尾的空格（U+0020）、水平制表（U+0009）、回车
  （U+000D）、换行（U+000A）四种字节，N 从裁完之后的第一个字节数起。被去掉的
  只有这四种：U+00A0、U+3000、垂直制表 U+000B 等都不是合法 JSON 空白，不会被
  裁掉（它们会令该行因 JSON 语法错误失败，那类原因不带字节位置）。
- **N 不是整批输入的累计位置。** 它永远相对当前这一行：此前各行的所有字节都不
  计入。记录里的 `line` 仍是**原始物理行号**：前面的空白行会占用行号、使该行
  的 `line` 增大，却不会给当前行的 N 增加一个字节。
- **N 也不是屏幕上显示的第几个字。** 它按该行在**输入时实际占用的字节**计数：
  - 中文通常每个字 3 个字节，常见表情每个 4 个字节；这些字节全部计入 N。
  - 反斜线转义按它在输入里的原始写法计数。一个 `\uXXXX` 转义是 6 个 ASCII
    字节（反斜线、`u`、四个十六进制位），正确配对的一对代理项转义
    `\uD83D\uDE00` 是 12 个字节——不能按“解码后的一个字符”算成 1。
  - **对象内部的空白仍占字节**：`{` 之后、成员之间多写的空格/制表符会计入 N；
    只有行首行尾被裁掉的那四种空白不计。制表符按 1 个字节计，不是按屏幕跳格列
    计。
- **起点不会因损坏所在的层级而改变。** 即使损坏出现在未知字段的嵌套对象或数组
  里（包括输入自带的 `extra` 内部），N 仍然从整行裁边后的开头数起，**不会**改成
  从该字段名、字段值或某个内层对象的开头数起。

因此，拿到 `line` 与 N 后定位原始字节的方法是：取该物理行的原始字节，先去掉行
首行尾的空格、制表、回车、换行，再在结果里取第 N 个字节（零基）。一个可直接用
的离线小工具：

```python
# save as locate.py: python3 locate.py logs.jsonl <line> <N>
import sys
path, line_no, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
raw = open(path, "rb").read().split(b"\n")[line_no - 1]
if raw.endswith(b"\r"):
    raw = raw[:-1]
content = raw.strip(b" \t\r\n")          # 与规范化裁掉的四种字节一致
if not 0 <= n < len(content):
    sys.exit(f"N={n} 超出该行范围（有效长度 {len(content)} 字节）")
print("byte at N =", hex(content[n]))
print("context    =", content[max(0, n - 12): n + 8])
```

#### 两类损坏，N 指向的位置含义不同

- **非法 UTF-8：指向“最先不能组成合法字符”的字节。** 扫描从行内容开头按字节
  前进，N 落在第一个无法开始或无法继续一个合法 UTF-8 字符的字节上。若是一个被
  截断的多字节序列（例如三字节序列只来了两个字节 `E2 80`），N 指向该序列的
  **起始字节**（这里是 `E2`），而不是序列内部或缺字节的“下一个空位”。孤立的
  延续字节（如 `80`）、超长编码、UTF-8 编码的代理项等同理，都指向第一个坏字节。
  原因固定是 `invalid UTF-8 encoding at byte offset N`。
- **未配对代理项转义：指向有问题的转义开头的反斜线。** JSON 字符串里单独出现的
  高代理项（`\uD800`–`\uDBFF`，后面没有紧接低代理项转义）或单独出现的低代理项
  （`\uDC00`–`\uDFFF`，前面没有高代理项转义）都非法，N 指向这段转义的第一个
  字节，即反斜线 `\`（不是 `u`，也不是四位码点的第一位）。原因会区分高、低
  代理项：
  - 高代理项：`unpaired Unicode escape \uXXXX at byte offset N: high surrogate
    must be followed immediately by a low surrogate escape`；
  - 低代理项：`unpaired Unicode escape \uXXXX at byte offset N: low surrogate
    must follow a high surrogate escape`。

#### 一行两种问题：先报告非法 UTF-8

字符完整性检查先做整行 UTF-8 合法性扫描，再扫描字符串里的代理项转义。因此一行
**同时**含有非法字节与未配对代理项转义时，**先报告非法 UTF-8**，N 是那个坏字节
自己的偏移——即使未配对转义在行里写得更靠前。所以 N 不是“所有错误里位置最靠前
的一处”，而是“按固定检查顺序首先命中的那类问题”里、该问题自身的位置。把非法
字节改好后再跑一次，才会看到（可能更靠前的）未配对转义。

#### 例一：中文在前的坏转义——行首空白与对象内部空白对 N 的影响

下面这行在动作字符串里先写两个中文字“登录”（各 3 字节），再写一段未配对的高
代理项转义文本 `\uD800`（6 个 ASCII 字节）。用一个三行批次演示：第 1 行原样，
第 2 行留空白（占行号），第 3 行行首加两个空格，第 4 行把两个空格挪进对象内部
（`{` 后两个空格、逗号后一个空格）。

```bash
line='{"timestamp":"2026-01-02T00:00:00Z","action":"登录\uD800"}'
printf '%s\n\n%s\n%s\n' \
  "$line" \
  "  $line" \
  '{  "timestamp":"2026-01-02T00:00:00Z", "action":"登录\uD800"}' \
  | ./bin/relayproof normalize
echo "exit=${PIPESTATUS[1]}"
```

标准输出（第 2 行是空白行、无记录，所以三条失败的行号是 1、3、4；退出状态
`1`，标准错误为空）：

```json
{"line":1,"ok":false,"error":"unpaired Unicode escape \\uD800 at byte offset 52: high surrogate must be followed immediately by a low surrogate escape"}
{"line":3,"ok":false,"error":"unpaired Unicode escape \\uD800 at byte offset 52: high surrogate must be followed immediately by a low surrogate escape"}
{"line":4,"ok":false,"error":"unpaired Unicode escape \\uD800 at byte offset 55: high surrogate must be followed immediately by a low surrogate escape"}
```

逐行核对第 1 行的 N=52：行内容没有行首空白要裁，到反斜线为止依次是——ASCII
前缀 `{"timestamp":"2026-01-02T00:00:00Z","action":"` 共 46 个字节，加上“登录”
的 6 个字节（每个中文字 3 字节），`46 + 6 = 52`，正好落在转义开头的反斜线上。
它不是“第几个字”：按显示字符数，反斜线大约是第 49 个字；按字节才是 52。

- 第 3 行行首多了两个空格：它们是被裁掉的合法 JSON 空白，所以 **N 仍是 52**；
  只是这行物理行号因前面的空白行变成了 3。
- 第 4 行把同样数目的空白放进对象内部（`{` 后 2 个、逗号后 1 个，共 3 个字节）：
  对象内部空白不裁、**占字节**，同一个反斜线的位置变成 **55 = 52 + 3**。

把“登录”换成一个 4 字节表情（如 `😀`，`F0 9F 98 80`）时，N 会是 50（46 + 4），
同样是按字节而非按字。损坏若在未知字段的嵌套对象或数组里，N 也仍是这样从整行
开头数起，不会从内层字段重新算起。

#### 例二：较早的坏转义与较晚的非法字节共存

这一行在动作字符串里先写未配对高代理项转义 `\uD800`（6 个 ASCII 字节，反斜线
位于 N=46），再放一个**原始非法字节 0xFF**（N=52）。为了能准确重建这个字节，
不要只在终端里照抄一个显示为“�”的字符；下面的 `printf` 用八进制 `\377` 明确
生成 0xFF（八进制 377 = 十六进制 FF），`\\uD800` 则生成 6 个普通 ASCII 字符
（反斜线加 `uD800`），也就是 JSON 源里那段转义文本：

```bash
tail=$(printf '\\uD800\377')          # 6 个 ASCII 字符 \uD800，随后 1 个原始字节 FF
printf '%s\n' "{\"timestamp\":\"2026-01-02T00:00:00Z\",\"action\":\"${tail}\"}" > bad.jsonl
tail -c 10 bad.jsonl | xxd           # 看清行尾真实字节
./bin/relayproof normalize < bad.jsonl
echo "exit=$?"
```

`xxd` 证明行尾确实是 6 个转义文本字节后跟一个 `ff`（而不是若干被替换过的
字符）：

```text
00000000: 5c75 4438 3030 ff22 7d0a                 \uD800."}.
```

标准化结果（退出状态 `1`，标准错误为空）：

```json
{"line":1,"ok":false,"error":"invalid UTF-8 encoding at byte offset 52"}
```

虽然未配对转义在更前面（N=46），报告的却是**非法 UTF-8**，位置是坏字节自己的
N=52——因为整行 UTF-8 扫描先于代理项转义扫描。用上文的 `locate.py`
（`python3 locate.py bad.jsonl 1 52`）可以确认第 52 个字节正是 `0xff`：

```text
byte at N = 0xff
context    = b'n":"\\uD800\xff"}'
```

把这个 0xFF 删掉、只留 `\uD800` 再跑一次，才轮到转义被报告，位置回到它自己的
46（原因后缀为高代理项说明）；若转义换成单独的低代理项（如 `\uDC00`），位置
同样指向反斜线，原因后缀则变成低代理项说明。

这与[多处错误的报告顺序](#多处错误的报告顺序)并不冲突：字段顺序只适用于**已经
通过字符完整性检查、并成功解析为 JSON 对象**的日志；上面两类失败发生在更早的
字符完整性阶段，失败记录同样只有一个 `error`、不带 `event`，逐行失败仍按现有
格式输出，命令行退出 `1`、标准错误为空（读取/写出中断才是退出 `2`）。

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
- 空白行不产生任何输出，但仍占用一个物理行号。这里的“空白行”按 Unicode 空白
  判定，含整行只有 U+00A0/U+3000 等特殊空白的行；它们被跳过并不意味着这些字符
  能充当 JSON 分隔符——区别详见
  [空白字符：整行、JSON 分隔符与字符串内容](#空白字符整行json-分隔符与字符串内容)。

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

### 按来源网段筛选：`--source-cidr`

`normalize` 接受可选参数 `--source-cidr`，只输出规范化后 `source_ip` 落在某一个
网段内的**成功事件**。一个参数只指定一个网段，网段可以是 IPv4 或 IPv6，且只
匹配与自身同族的地址。该参数支持 `--source-cidr 192.0.2.0/24`（值作为下一参数）
与 `--source-cidr=192.0.2.0/24`（等号连写）两种写法：

```bash
./bin/relayproof normalize --source-cidr 192.0.2.0/24 < logs.jsonl
./bin/relayproof normalize --source-cidr 2001:db8::/64 < logs.jsonl
```

#### 网段参数的写法

- IPv4：点分十进制地址加斜线和 0 至 32 的前缀长度，例如
  `192.0.2.0/24`、`10.0.0.0/8`、`0.0.0.0/0`、`192.0.2.1/32`。
- IPv6：合法 IPv6 地址加斜线和 0 至 128 的十进制前缀长度，支持压缩写法
  （`2001:db8::1`、`::1`）与完整写法（`2001:db8:0:0:0:0:0:1`），地址不带端口
  或区域标识（`%eth0`），例如 `2001:db8::/64`、`fe80::/10`、`::/0`、`::1/128`。
- 地址里的**主机位按网段解释**（直接掩掉，不报错）：`192.0.2.123/24` 与
  `192.0.2.0/24` 的筛选范围完全相同，`2001:db8::1234/64` 与
  `2001:db8::/64` 选中同一范围。Go 入口 `ParseSourceCIDRFilter(...).String()`
  也返回掩掉主机位后的标准网段写法（如 `2001:db8::/64`）。
- `/32`（IPv4）、`/128`（IPv6）只匹配那一个地址；`0.0.0.0/0` 匹配所有规范化后
  仍是 IPv4 的来源，`::/0` 匹配所有规范化后仍是 IPv6 的来源。
- 不接受越界八位组（`256.0.0.0/8`）、越界前缀（IPv4 `/33`、IPv6 `/129`）、
  补零写法（`192.168.001.0/24`、`/024`、`2001:db8::/064`）、非法 IPv6 地址
  （`1::2::3/64`、带端口 `[2001:db8::1]:443/64`、带区域 `fe80::1%eth0/64`），
  也不接受缺值、空值。
- 参数地址若为 **IPv4 映射 IPv6**（如 `::ffff:192.0.2.0/120`、
  `::ffff:c000:0201/120`），**拒绝该参数**并提示改用 IPv4 网段，不自动换算
  前缀长度（例如 `/120` 在 128 位里留下 8 个主机位，等价于 IPv4 的 `/24`，
  即 `192.0.2.0/24`，但程序不替调用方做这层转换）。

#### 命中规则

筛选以**完整规范化后的 `source_ip`** 为准，与字段是用标准名 `source_ip` 还是
别名 `src_ip` 提供无关，也与 IPv6 采用压缩还是完整（等价）写法无关；别名仍沿用
既有的映射与冲突判断。

- **两类网段各自只匹配对应地址类型。** `192.0.2.1` 与 `::ffff:192.0.2.1`
  规范化后是同一个 IPv4 地址，只能命中 IPv4 网段，任何 IPv6 网段（含 `::/0`）
  都不命中它们；反过来 IPv6 网段也不会命中规范化为点分形式的 IPv4 来源。
- `::192.0.2.1` 仍然是真正的 IPv6 地址（规范化为 `::c000:201`），即使末尾 32
  位与某 IPv4 地址相同，也**不会**命中 IPv4 网段；它可以命中包含它的 IPv6 网段
  （如 `::/96`）。
- 合法事件没有来源地址、来源属于另一地址族、或位于网段之外时：**不输出该成功
  记录，也不把它算作失败**。因此一次全合法但全部被筛掉的运行，标准输出为空、
  退出状态仍为 `0`。
- 命中的成功记录沿用现有 JSON 结构和内容，**不增加任何筛选标记**。输出保持
  输入次序，`line` 仍是原始物理行号；被筛掉的行与空白行一样不会让后续行重新
  编号。时间与动作的规范化、`extra` 的成员边界以及大整数等证据的数字写法均
  保持原有规则；末行没有换行时也照常处理。

#### 筛选不能掩盖坏日志

筛选只作用于**成功事件**。即使某行的地址不在所选网段、属于另一地址族、该行没有
来源地址，只要该行按现有规则规范化失败，就仍输出失败记录：带原物理行号和原有
错误原因、没有 `event`，并照常计入失败数；后续日志继续处理。因此“输入输出正常
结束但有失败行”仍退出 `1`，哪怕该失败行的地址（若有的话）本会被筛掉。读取或
写出故障的退出 `2` 与标准错误诊断也不变。

#### 参数错误

参数缺值、空值、不是上述 IPv4/IPv6 网段（含 IPv4 映射 IPv6 地址）、重复指定，
或出现其他无法识别的参数时，程序在**读取任何日志之前**就退出 `2`：标准错误给出
一行以 `normalize:` 开头、说明参数问题的诊断，标准输出为空。此时不能再用退出
状态判断日志是否合法——它属于参数/输入输出层面的 `2`，而非日志行层面的 `1`。

未指定 `--source-cidr` 时行为与以前完全一致。Go 公共入口
`relayproof.NormalizeReader(r, w)` 的签名与行为保持兼容；需要筛选时使用
`relayproof.NormalizeReaderFiltered(r, w, filter)`，其中 `filter` 由
`relayproof.ParseSourceCIDRFilter("192.0.2.0/24")` 或
`relayproof.ParseSourceCIDRFilter("2001:db8::/64")` 得到，传 `nil` 与
`NormalizeReader` 完全等价。

#### 例：IPv4 网段内成功事件与网段外失败行

```bash
./bin/relayproof normalize --source-cidr 192.0.2.0/24 <<'EOF'
{"timestamp":"2026-10-04T08:30:00Z","action":"login","source_ip":"192.0.2.7"}
{"timestamp":"2026-10-04T08:30:00Z","action":"login6","source_ip":"::192.0.2.7"}
{"timestamp":"2026-10-04T08:30:00Z","action":"other","source_ip":"198.51.100.7"}
{"timestamp":"bad","action":"broken","source_ip":"198.51.100.9"}
EOF
echo "exit=$?"
```

第 2 行是真正的 IPv6（`::c000:201`）、第 3 行在网段外，二者是合法事件但不输出；
第 4 行虽然地址在网段外，却仍是一条坏日志，照常输出失败记录。标准输出为
（退出状态 `1`，标准错误为空）：

```json
{"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","source_ip":"192.0.2.7","action":"login"}}
{"line":4,"ok":false,"error":"field \"timestamp\": invalid RFC3339 timestamp: not an RFC3339 timestamp (need YYYY-MM-DDTHH:MM:SS with two-digit fields, a dot fraction of 1-9 digits, and Z or ±HH:MM offset)"}
```

#### 例：IPv6 网段筛选与地址族边界

```bash
./bin/relayproof normalize --source-cidr 2001:db8::1234/64 <<'EOF'
{"timestamp":"2026-10-04T08:30:00Z","action":"v6-in","source_ip":"2001:db8::1"}
{"timestamp":"2026-10-04T08:30:00Z","action":"v6-in-full","src_ip":"2001:db8:0:0:0:0:0:2"}
{"timestamp":"2026-10-04T08:30:00Z","action":"v6-other","source_ip":"2001:db8:1::1"}
{"timestamp":"2026-10-04T08:30:00Z","action":"v4","source_ip":"192.0.2.1"}
{"timestamp":"2026-10-04T08:30:00Z","action":"mapped","source_ip":"::ffff:192.0.2.1"}
{"timestamp":"2026-10-04T08:30:00Z","action":"compat","source_ip":"::192.0.2.1"}
EOF
echo "exit=$?"
```

参数里的主机位被掩掉，实际筛选 `2001:db8::/64`。第 1、2 行（压缩/完整写法、标准
名/别名）命中，其余四条虽都是合法事件，却一律不输出，标准输出只有两行（退出
`0`）：

```json
{"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","source_ip":"2001:db8::1","action":"v6-in"}}
{"line":2,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","source_ip":"2001:db8::2","action":"v6-in-full"}}
```

被筛掉的四条各属一种情形：第 3 行 `2001:db8:1::1` 是网段**外**的 IPv6；第 4 行
`192.0.2.1` 是 IPv4；第 5 行 `::ffff:192.0.2.1` 规范化后也是 IPv4（`192.0.2.1`），
IPv6 网段不匹配另一地址族；第 6 行 `::192.0.2.1` 规范化为 `::c000:201`，仍是 IPv6
但不在 `2001:db8::/64` 内。把网段换成包含它的 `--source-cidr ::/96` 再跑一次，
只有第 6 行命中（输出 `source_ip` 为 `::c000:201`），第 4、5 行的 IPv4 来源依旧
不命中，第 1、2、3 行则因落在 `::/96` 之外而被筛掉。

### 空白字符：整行、JSON 分隔符与字符串内容

`normalize` 按换行划分物理行。同一个“空白”字符落在不同位置，结果完全不同，
按三种位置说明；下列结论都可用本节命令离线复现。

| 位置 | 哪些字符算空白 | 结果 |
|---|---|---|
| 独占一整行 | 任意 Unicode 空白（见位置一） | 整行跳过：占用行号、无输出、不计失败 |
| JSON 对象之外或成员之间 | 仅空格 U+0020、水平制表 U+0009、回车 U+000D、换行 U+000A 四种 | 其余字符（含 U+00A0、U+3000、U+000B）令该行因 JSON 语法错误失败 |
| JSON 字符串值内部（`action`、未知字段等） | 不是分隔符，是普通字符 | 按该字段的值规则处理（`action` 去首尾空白；未知字段原样进 `extra`） |

#### 位置一：整行只有空白 —— 跳过

`NormalizeReader` 对每个物理行先做“是否为空白行”判定：去掉 Unicode 空白后为
空就跳过。因此仅含不换行空格 U+00A0（UTF-8 字节 `c2 a0`）、全角空格 U+3000
（`e3 80 80`）、垂直制表 U+000B、换页 U+000C，或只由空格/制表/回车/换行混合
而成的行，都与空行同等对待。被跳过的行**仍占用一个物理行号**，不产生结果，也
**不计入失败**。

例：两条合法日志中间夹一行只有 U+00A0 的行（退出状态 `0`，标准错误为空）。

```bash
NBSP=$'\xc2\xa0'   # 仅含不换行空格 U+00A0 的一行；换成 $'\xe3\x80\x80' 即全角空格 U+3000
printf '%s\n%s\n%s\n' \
  '{"timestamp":"2026-10-04T08:30:00Z","action":"login"}' \
  "$NBSP" \
  '{"timestamp":"2026-10-04T09:00:00Z","action":"logout"}' \
  | ./bin/relayproof normalize
echo "normalize exit=${PIPESTATUS[1]}"
```

逐行输出（中间行占用第 2 行但没有任何记录，所以两条成功记录是 `line:1` 与
`line:3`）：

```json
{"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","action":"login"}}
{"line":3,"ok":true,"event":{"timestamp":"2026-10-04T09:00:00Z","action":"logout"}}
```

注意：**整行被跳过，不表示这些字符能当 JSON 分隔符。** 空白行判定按 Unicode
空白处理；只要同一行还带有 JSON 对象，对象之外与成员之间就只认下面位置二的
四种 JSON 空白。

#### 位置二：对象之外、成员之间只接受四种 JSON 空白

RFC 8259 的 JSON 语法只允许空格（U+0020）、水平制表（U+0009）、回车
（U+000D）、换行（U+000A）出现在记号之间。规范化在解析前只裁掉文档首尾的这
四种字符（刻意不用会额外吞掉 U+00A0、U+3000、U+000B 的 `bytes.TrimSpace`），
目的就是让非法分隔符原样到达解析器并被拒绝，而不是被悄悄删除。

- **换行 U+000A 会结束当前物理行。** `normalize` 是逐行入口，不能用换行把一个
  对象拆成多行喂入；拆开的两半各自成行、各自失败（退出状态 `1`，标准错误为空）：

  ```console
  $ printf '%s\n%s\n' '{"timestamp":"2026-10-04T08:30:00Z",' '"action":"login"}' \
      | ./bin/relayproof normalize
  {"line":1,"ok":false,"error":"invalid JSON: EOF"}
  {"line":2,"ok":false,"error":"log must be a JSON object"}
  ```

- **U+00A0、U+3000、垂直制表 U+000B 出现在对象前后或成员之间，都是 JSON 语法
  错误。** 例：三行输入，第 2 行的对象前多了一个 U+00A0，前后各一条合法日志：

  ```bash
  NBSP=$'\xc2\xa0'
  printf '%s\n%s\n%s\n' \
    '{"timestamp":"2026-10-04T08:30:00Z","action":"login"}' \
    "${NBSP}{\"timestamp\":\"2026-10-04T08:31:00Z\",\"action\":\"deny\"}" \
    '{"timestamp":"2026-10-04T09:00:00Z","action":"logout"}' \
    | ./bin/relayproof normalize
  echo "normalize exit=${PIPESTATUS[1]}"
  ```

  逐行输出：失败记录带**原物理行号** `line:2`、`ok:false` 和原因，不带 `event`；
  第 3 行不受影响、继续输出。退出状态为 `1`，标准错误为空：

  ```json
  {"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","action":"login"}}
  {"line":2,"ok":false,"error":"invalid JSON: invalid character 'Â' looking for beginning of value"}
  {"line":3,"ok":true,"event":{"timestamp":"2026-10-04T09:00:00Z","action":"logout"}}
  ```

  原因里的 `Â` 是 U+00A0 的 UTF-8 首字节 `c2` 被解析器按字节报告的结果，它不会
  被当作空格。同一位置换成 U+3000 报 `invalid character 'ã' after object
  key:value pair`（`ã` 对应其首字节 `e3`），换成 U+000B 报
  `invalid character '\v' ...`。把该字符放到成员之间（例如整行用
  `$'{"timestamp":"2026-10-04T08:30:00Z"\xc2\xa0,"action":"login"}'` 给出）同样
  失败，原因后缀为 `after object key:value pair`。

- **对象之外的反斜杠文本不是空格，也不是转义。** 在字符串**外面**写下六个 ASCII
  字符——反斜杠、`u`、`0`、`0`、`a`、`0`，即展示记法 `\u00a0`——它不会被当成
  不换行空格，甚至不是合法记号：

  ```console
  $ printf '%s\n' "$(printf '\\u00a0'){\"timestamp\":\"2026-10-04T08:30:00Z\",\"action\":\"login\"}" \
      | ./bin/relayproof normalize
  {"line":1,"ok":false,"error":"invalid JSON: invalid character '\\' looking for beginning of value"}
  ```

  `\u00a0` 这种 `\uXXXX` 形式的转义只在 **JSON 字符串内部**才会被解释（见位置
  三）；对象之外那只是一个以反斜杠开头的语法错误。不要把展示用的转义记法
  `\u00a0` 与真正的 U+00A0 字符混为一谈。

#### 位置三：字符串内容里是普通字符

进入 JSON 字符串后，这些字符是字符串值的一部分，不再是分隔符。

- **`action`：去首尾空白，保留中间字符，纯空白动作失败。** 去空白用的是按
  Unicode 识别空白的 `strings.TrimSpace`，因此 U+00A0、U+3000 与普通空格一样
  会被从首尾去掉，而字符串中部的字符原样保留。下例的动作在首尾和中部各放一个
  U+00A0：

  ```bash
  NBSP=$'\xc2\xa0'
  printf '%s\n' "{\"timestamp\":\"2026-10-04T08:30:00Z\",\"action\":\"${NBSP}lo${NBSP}gin${NBSP}\"}" \
    | ./bin/relayproof normalize
  ```

  标准输出（首尾两个 U+00A0 被去掉，中部的保留；退出状态 `0`）：

  ```json
  {"line":1,"ok":true,"event":{"timestamp":"2026-10-04T08:30:00Z","action":"lo gin"}}
  ```

  中部那个 U+00A0 在终端里与普通空格难以区分，用 `cat -v` 可看到它的 UTF-8
  字节（`M-BM- ` 即 `c2 a0`）：

  ```text
  ...,"action":"loM-BM- gin"}}
  ```

  若动作值改用 JSON 转义拼写，即在字符串内部写六字符转义
  `"action":"\u00a0lo\u00a0gin\u00a0"`，JSON 解析会在字符串内部把它还原成同一个
  U+00A0，规范化后的字节与上例完全相同；这与位置二中“字符串之外的反斜杠文本
  非法”并不矛盾。若整个动作去掉首尾空白后为空（例如 `"action":"   "`、
  `"action":"\u00a0"`，或全为 U+3000），则失败为
  `field "action": action must not be empty`（退出状态 `1`）。

- **未知字段：首尾空白作为证据原样保留。** 未参与映射的字段进入 `extra`（见
  [扩展字段 extra：成员边界与证据值保留](#扩展字段-extra成员边界与证据值保留)），
  映射不会进入这些字符串，更不会做动作那样的去首尾空白：

  ```bash
  NBSP=$'\xc2\xa0'
  printf '%s\n' "{\"timestamp\":\"2026-10-04T08:30:00Z\",\"action\":\"login\",\"note\":\"${NBSP}hi${NBSP}\"}" \
    | ./bin/relayproof normalize
  ```

  输出中 `note` 首尾的 U+00A0 都还在（退出状态 `0`）；`cat -v` 下清晰可见
  （`M-BM- ` 即 U+00A0）：

  ```text
  ...,"extra":{"note":"M-BM- hiM-BM- "}}
  ```

  未知字段的值以原始 JSON（`json.RawMessage`）携带：源日志若直接写 U+00A0
  字节，输出就保留这两个字节；源日志若写成 `\u00a0` 转义，输出也保留这段转义
  拼写。无论哪种写法，首尾空白都不会被修剪。

#### Go 入口差异：NormalizeReader 跳过整行，NormalizeLine 不跳过

上述“整行只有空白就跳过”是 `NormalizeReader` 逐行读取时的判定。直接调用
`NormalizeLine(lineNo int, raw []byte)` 时没有这一步：它只裁掉文档首尾的四种
JSON 空白（空格、制表、回车、换行），随后按 JSON 解析。因此把同一行只有
U+00A0 的内容直接交给 `NormalizeLine`，得到的是一条 JSON 语法失败结果，而不是
“跳过”：

```go
res := relayproof.NormalizeLine(2, []byte("\xc2\xa0\n"))
```

```json
{"line":2,"ok":false,"error":"invalid JSON: invalid character 'Â' looking for beginning of value"}
```

需要“空白行跳过、物理行号连续、失败计数”这套逐行语义时应使用 `NormalizeReader`
（命令行 `normalize` 就是它的薄封装）；只有在自行按行读取、且希望每个物理行都
拿到一条结果时，才直接调用 `NormalizeLine`。

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

入口差异：空白行（含整行只有 U+00A0、U+3000 等特殊空白的行）被整体跳过、占用
行号却无结果，是 `NormalizeReader` 逐行读取时的规则。若绕过它直接调用
`NormalizeLine(lineNo, raw)`，同一行特殊空白不会被跳过，而是返回一条 JSON 语法
失败结果；详细对比与示例见
[空白字符：整行、JSON 分隔符与字符串内容](#空白字符整行json-分隔符与字符串内容)。

#### 什么才算“干净的 EOF”：包装与组合错误

`NormalizeReader` 判断“输入正常结束”看的不是 `errors.Is(err, io.EOF)`，而是
**这个错误里除了 `io.EOF` 什么都没有**：

- 直接返回 `io.EOF`：正常结束；
- 外面包一层或多层 `%w`（如 `fmt.Errorf("connection closed: %w", io.EOF)`）：
  仍是正常结束；
- 用 `errors.Join` 组合，但每个底层原因都只是 `io.EOF`（如
  `errors.Join(io.EOF, io.EOF)`）：仍是正常结束；
- 一旦组合里除了 `io.EOF` 还有**另一个独立的读取原因**（如
  `errors.Join(io.EOF, deviceErr)`，以及它外面再套任意层 `%w` 包装）：这是
  **读取中断**。此时 `errors.Is(err, io.EOF)` 照样成立——所以不能用它判断
  本次读取是否成功结束。

正常结束时，即使最后一条日志没有末尾换行符，也会作为最后一条完整日志处理，
物理行号照常计数。读取中断时，随这次失败读取**同一批交付**的字节要分开看：

- 已以换行结束的完整日志仍**按原顺序逐条处理**：合法的成功、字段无效的照常
  计入 `failures`、空白行照样占用行号但无输出；
- 剩下那个没有换行的末尾片段属于这次失败读取的一部分，不是完整日志行：
  **不产生任何结果，也不计入 `failures`**，即使它本身是一条完全合法的日志。

处理在故障当次读取后立即停止，不会再发一次 `Read` 去“确认”结尾。

#### 完整示例：同一批日志的两种结局

下面的程序只依赖标准库与本项目，可直接放进任何引用本模块的工程里离线运行
（脚本化的 `oneShotReader` 在第一次 `Read` 时一次性交付全部字节并同时返回
指定错误，用来确定性地复现“最后一批字节与错误同批到达”）：

```go
package main

import (
    "bytes"
    "errors"
    "fmt"
    "io"

    "github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

var errInputDevice = errors.New("input device reset")

// oneShotReader 在第一次 Read 时一次性交付 data，并同时返回 err。
type oneShotReader struct {
    data      []byte
    err       error
    delivered bool
}

func (r *oneShotReader) Read(p []byte) (int, error) {
    if r.delivered {
        return 0, io.EOF
    }
    r.delivered = true
    return copy(p, r.data), r.err
}

// 同一批输入：第 1 行合法，第 2 行时间字段无效，第 3 行合法且没有末尾换行。
const batch = "" +
    `{"timestamp":"2026-01-02T00:00:00Z","action":"ok-1"}` + "\n" +
    `{"timestamp":"not-a-time","action":"bad-2"}` + "\n" +
    `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-3"}`

func main() {
    // 情形一：干净 EOF，正常结束。
    var out bytes.Buffer
    failures, err := relayproof.NormalizeReader(
        &oneShotReader{data: []byte(batch), err: io.EOF}, &out)
    fmt.Printf("[A] output:\n%s", out.String())
    fmt.Printf("[A] failures=%d err=%v\n\n", failures, err)

    // 情形二：同一次 Read 同时给出 io.EOF 与另一个独立读取原因。
    combined := errors.Join(io.EOF, errInputDevice)
    out.Reset()
    failures, err = relayproof.NormalizeReader(
        &oneShotReader{data: []byte(batch), err: combined}, &out)
    fmt.Printf("[B] output:\n%s", out.String())
    fmt.Printf("[B] failures=%d\nerr=%v\n", failures, err)
    fmt.Printf("[B] Is(ErrLogRead)=%v Is(errInputDevice)=%v Is(ErrLogWrite)=%v\n\n",
        errors.Is(err, relayproof.ErrLogRead),
        errors.Is(err, errInputDevice),
        errors.Is(err, relayproof.ErrLogWrite))

    // 情形三：故障只带着一个没有换行的合法片段，此前没有任何完整行。
    fragment := `{"timestamp":"2026-01-02T00:00:00Z","action":"tail-3"}`
    out.Reset()
    failures, err = relayproof.NormalizeReader(
        &oneShotReader{data: []byte(fragment), err: combined}, &out)
    fmt.Printf("[C] output empty=%v failures=%d Is(ErrLogRead)=%v Is(errInputDevice)=%v\n",
        out.Len() == 0, failures,
        errors.Is(err, relayproof.ErrLogRead),
        errors.Is(err, errInputDevice))
}
```

实际输出（错误文字中的换行来自 `errors.Join` 的标准格式）：

```text
[A] output:
{"line":1,"ok":true,"event":{"timestamp":"2026-01-02T00:00:00Z","action":"ok-1"}}
{"line":2,"ok":false,"error":"field \"timestamp\": invalid RFC3339 timestamp: not an RFC3339 timestamp (need YYYY-MM-DDTHH:MM:SS with two-digit fields, a dot fraction of 1-9 digits, and Z or ±HH:MM offset)"}
{"line":3,"ok":true,"event":{"timestamp":"2026-01-02T00:00:00Z","action":"tail-3"}}
[A] failures=1 err=<nil>

[B] output:
{"line":1,"ok":true,"event":{"timestamp":"2026-01-02T00:00:00Z","action":"ok-1"}}
{"line":2,"ok":false,"error":"field \"timestamp\": invalid RFC3339 timestamp: not an RFC3339 timestamp (need YYYY-MM-DDTHH:MM:SS with two-digit fields, a dot fraction of 1-9 digits, and Z or ±HH:MM offset)"}
[B] failures=1
err=log stream read failure: EOF
input device reset
[B] Is(ErrLogRead)=true Is(errInputDevice)=true Is(ErrLogWrite)=false

[C] output empty=true failures=0 Is(ErrLogRead)=true Is(errInputDevice)=true
```

对照输入逐行看两种结局：

- **情形 A（正常结束）**：第 1 行成功；第 2 行是字段无效日志，输出一条
  `ok:false` 记录并使 `failures=1`，但它**不会让 `err` 非空**——逐行失败
  从来不是流级错误；没有末尾换行的第 3 行在干净 EOF 下照常处理，成为
  `line:3` 的成功记录。最终 `failures=1, err=<nil>`。
- **情形 B（读取中断）**：同批三行中只有以换行结束的第 1、2 行按原顺序
  处理，输出与 A 的前两行完全一致、`failures` 同样为 1（只来自第 2 行）；
  第 3 行虽然是合法日志，但它作为无换行片段随故障一起到达，**不留记录、
  不占失败数**。`err` 包着 `ErrLogRead`，且上游自己的原因
  `errInputDevice` 仍可由 `errors.Is` 识别；`errors.Is(err, io.EOF)` 虽然
  成立却不能当成功依据。若组合错误外面再套 `fmt.Errorf("...: %w", ...)`，
  结论不变。
- **情形 C（只有未结束片段）**：整批输入只有一个没有换行的合法片段时，
  **输出为空、`failures=0`，但 `err` 仍报告读取中断**。所以“没看到失败
  记录、失败数也是 0”不代表输入完整处理完了——接入方必须先判断 `err`，
  不能用 `failures == 0` 或输出为空代替。

#### 读取与写出同时失败时，按谁归因

读、写故障可能在同一次处理中都发生。归因只取决于**写出故障发生的那一刻，
手上是否已经有读取故障**，对应两种实际发生条件：

1. **一次读取已经返回故障及完整日志，随后写出这些结果失败。** 读取故障在
   故障发生的当次 `Read` 就被记录（早于同批字节的任何写出），因此它始终是
   主要原因，与写出失败发生在哪个阶段无关——既可能是写出某条超长结果时
   当场失败（它会逼出对此前缓冲结果的物理写入），也可能是输入处理结束后
   收尾 `Flush` 时失败。返回错误保持 `ErrLogRead` 包原读取原因这一条链：
   `errors.Is(err, relayproof.ErrLogRead)` 与
   `errors.Is(err, 上游读取原因)` 都成立；**后来的写出原因只出现在错误文字
   中**，既不包进错误链，也不作为 `errors.Join` 成员加入，因此
   `errors.Is(err, relayproof.ErrLogWrite)` 与对写出原因的 `errors.Is` 都为
   `false`。
2. **写出失败时尚未收到任何读取故障。** 立即按写出故障报告
   （`ErrLogWrite` 与写出原因都在可匹配的错误链中），处理当场停止，
   **不会为了决定归因再继续读取后续输入**。

两种情况下 `failures` 都只统计此前已处理完整行中的逐行失败，I/O 故障不改动
这个计数；输出端可能残留一条写了一半的末条 JSON（写出端少接收字节却返回
`nil` 时同样按 `io.ErrShortWrite` 归入写出故障），中断后不应再在该 writer 上
追加内容。命令行入口对两类流级故障都以退出 `2` 结束并在标准错误给出
`normalize:` 诊断。

`--source-cidr` 来源网段筛选（Go 侧为 `NormalizeReaderFiltered`）只筛掉
**成功事件**：网段外的坏日志仍输出失败记录，流级读取/写出中断也照常返回，
筛选既不会把中断变成正常结束，也不改变上述读写归因。

上述全部边界——含干净 EOF 的三种形态、包装后的组合错误、仅片段到达，以及
读写同时失败的两种归因——都有一个只依赖标准库与本项目、可在本机离线运行的
完整程序：

```bash
go run ./examples/normalizeeof
```

它用内存 reader/writer 脚本化每一种故障，逐条打印实际输出记录、`failures`、
错误文字与各 `errors.Is` 的判定结果。

## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
