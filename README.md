# 跨链消息与轻客户端验证服务

## 用途

轻客户端头同步、消息封装与投递、重放防护、中继重试与超时、储备与状态证明校验、跨链可观测。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `relayproof/`，命令入口位于 `cmd/relayproof/`。

```bash
go run ./cmd/relayproof demo
go run ./cmd/relayproof version
go run ./cmd/relayproof verify            # 确定性端到端验证（自动用临时目录）
go test ./...
```

## 本地持久消息队列

`relayproof.Queue` 是一个只依赖标准库与本地磁盘的投递队列，状态目录由用户指定。
打开目录即取得排他进程锁；投递成功仅表示消息进入本地成功记录，同时消费
`(来源链, 目标链, nonce)` 组合，不需要连接真实链或收件服务。

```bash
BIN=./relayproof            # 或 go run ./cmd/relayproof
DIR=/var/lib/relayproof

# 登记来源链与头信息
$BIN queue register-source --state $DIR --chain chain-a
$BIN queue header --state $DIR --chain chain-a --height 100 --root 0x100 --trusted

# 提交消息（--expires-at 为 Unix 毫秒绝对过期时刻，0 表示不过期）
$BIN queue submit --state $DIR --id m1 --from chain-a --to chain-b \
  --nonce 7 --proof-at 100 --payload hello --expires-at 9000000000000

# 由用户提供处理时间（Unix 毫秒）推进；相同时间可重复推进，倒退被拒绝
$BIN queue advance --state $DIR --now 1700000000000

# 查询：原消息、状态、具体原因、下次重试时间
$BIN queue query --state $DIR --id m1
$BIN queue query --state $DIR
```

### 头信息与可信覆盖

头信息按来源链分别保存。一条消息能否投递，取决于其来源链**已接受的最高
可信头**是否达到消息的证明高度，与最近保存的头无关：

- 首个可信头建立覆盖范围；更高的可信头扩大覆盖范围。
- 较低的可信头、或任意高度的不可信头，都可以正常保存（成为该链最近保存
  的头），但不会降低已有的可信高度；保存一个比可信头更高的不可信头，也
  不能放行超出覆盖范围的消息。
- 保存头信息不等于登记来源链：来源链未登记时，即使已保存该链的可信头，
  其消息仍按 `unknown-source` 永久拒绝。
- 投递成功的原因引用实际采用的可信高度
  （`delivered; proof verified by trusted header at height N`），N 是已
  接受的最高可信头高度，而不是最近保存的头的高度；查询结果中的成功原因
  应据此解读。

同高度更新的边界：

- 新提交的可信头与当前最高可信头**同高且根相同**：正常接受，覆盖范围不
  变（幂等）。
- **同高但根不同**：返回可信头冲突，原可信头继续有效，队列仍可正常使用。
  根按原字符串比较，空根也是合法输入（同高空根同样幂等接受）。命令行遇
  到该冲突时输出 `error: trusted header conflict: different root at the
  accepted height: ...` 并以退出码 16 结束；注意与消息内容冲突（同一 ID
  提交不同内容，退出码 13）区分。
- 不可信头即使同高且根不同，也正常保存，不改变可信覆盖范围，不触发冲突。
- 较低可信头的根差异不属于上述冲突条件：它被正常保存，覆盖范围不变。

写入头信息本身从不触发消息处理：不增加等待消息的尝试次数，也不提前或推
迟已安排的重试时刻；等待消息只在其重试到期后的推进中重新判断。

### 示例：更新头信息后的投递判断

下面这组连续操作可离线复现，处理时间沿用用户指定 `--now` 的约定：

```bash
BIN=./relayproof
DIR=/var/lib/relayproof-demo

# 登记来源链，保存高度 100 的可信头，再保存高度 120 的不可信头
$BIN queue register-source --state $DIR --chain chain-a
$BIN queue header --state $DIR --chain chain-a --height 100 --root 0x100 --trusted
$BIN queue header --state $DIR --chain chain-a --height 120 --root 0x120

# 提交两条消息：证明高度 90（已被可信头 100 覆盖）与 110（尚未被覆盖）
$BIN queue submit --state $DIR --id m90 --from chain-a --to chain-b \
  --nonce 1 --proof-at 90 --payload hello
$BIN queue submit --state $DIR --id m110 --from chain-a --to chain-b \
  --nonce 2 --proof-at 110 --payload world

# 首次推进，处理时间 1700000000000
$BIN queue advance --state $DIR --now 1700000000000
# {"nowMs":1700000000000,"results":[
#   {"id":"m90","status":"success","reason":"delivered; proof verified by trusted header at height 100"},
#   {"id":"m110","status":"waiting","reason":"waiting for trusted header covering height 110 (current 100)"}]}
```

`m90` 成功，成功原因引用可信高度 100——更高的不可信头 120 不起作用；
`m110` 等待，首次重试安排在 1700000001000（第 1 次尝试后退避 1 秒）：

```bash
$BIN queue query --state $DIR --id m110
# {"id":"m110",...,"status":"waiting","reason":"waiting for trusted header covering height 110 (current 100)","attempts":1,"nextRetryMs":1700000001000}
```

随后保存能覆盖 110 的可信头。写头不触发处理：`m110` 的尝试次数与已安排
的重试时刻不变，查询结果与上面完全相同（原因文本仍记录上次处理时的可信
高度 100，要到下次处理才更新）：

```bash
$BIN queue header --state $DIR --chain chain-a --height 110 --root 0x110 --trusted
$BIN queue query --state $DIR --id m110
# {"id":"m110",...,"status":"waiting","reason":"waiting for trusted header covering height 110 (current 100)","attempts":1,"nextRetryMs":1700000001000}
```

重试尚未到期时推进，`m110` 不会被重新处理，结果为空：

```bash
$BIN queue advance --state $DIR --now 1700000000500
# {"nowMs":1700000000500,"results":null}
```

重试到期后再推进，`m110` 成功，成功原因引用新的可信高度 110：

```bash
$BIN queue advance --state $DIR --now 1700000001000
# {"nowMs":1700000001000,"results":[
#   {"id":"m110","status":"success","reason":"delivered; proof verified by trusted header at height 110"}]}
```

### 状态语义

| 状态 | 含义 | 是否终结 |
| --- | --- | --- |
| `pending` | 已提交，尚未首次处理 | 否 |
| `waiting` | 已处理，等待覆盖证明高度的可信头 | 否 |
| `success` | 本地成功记录已落盘且 nonce 已消费 | 是 |
| `replay` | nonce 组合已被另一条消息消费 | 是 |
| `expired` | 到达绝对过期时刻（恰好相等也算过期） | 是 |
| `unknown-source` | 来源链未登记，永久拒绝 | 是 |

- 同一 ID、相同内容重复提交返回已有记录，不新增队列项；内容不同返回冲突，
  原记录不变；终结记录不能再次提交，也不能靠更新头信息重新激活。
- 不同 ID 可复用相同 nonce 组合：最多一条成功，其余在处理时记为重放。
- 消费关系严格按三个独立值判断：`(来源链, 目标链, nonce)`。链名按原始
  UTF-8 内容逐字节区分，允许包含 `:` 或 U+0000 等任何字符；系统不依赖分隔
  字符拼接三个值，因此 `a:b→c` 与 `a→b:c`（以及 `a␀b→c` 与 `a→b␀c`，
  仅能通过 Go 接口提交）即使 nonce 相同也互不影响，各自最多成功一次。
- 每次推进先按首次提交顺序处理到期消息（新消息在下一次推进时首次处理），
  随后对所有未终结消息重新检查重放与过期；两者同时满足时按重放处理。
- 来源已登记但头不可信或高度不足时保持等待、不消费 nonce；更新头信息不
  绕过重试时间。等待重试间隔依次为 1、2、4、8、16、32 秒，之后 60 秒封顶，
  从实际处理时间计算；一次推进跨过多个间隔也只处理一次。重试时刻按
  `处理时间 + 退避间隔` 计算，并在 int64 上限（9223372036854775807）处饱和：
  当结果无法在 int64 中表示时，下次重试时刻记为上限本身，绝不会绕回负数、
  变成零，或早于本次处理时间。消息一旦在上限时刻处理过且仍在等待，之后所有
  合法推进都处于同一时刻，重试永不再到期：相同时间重复推进不会再次尝试、不会
  增加尝试次数，也不会重复报告 waiting，记录保持既有状态、原因、尝试次数与
  上限重试时刻；对所有未终结消息的重放与到期检查仍然照常生效，更新头信息也仍
  不触发处理、不绕过该等待。
- 待处理（未首次处理）与终结记录没有下次重试时间。

### 持久化与故障恢复

- 状态写入目录下的 `queue.log`：仅追加、帧带 CRC32 校验、每条记录 fsync
  后才确认成功；成功记录与 nonce 消费是同一条日志，不可能各自单独生效。
  成功记录以 `consumeFrom`/`consumeTo`/`consumeNonce` 三个独立字段连同
  `consumeBy` 落盘，链名（含 `:`、U+0000）逐字保留，不拼接成单个字符串。
- 突然退出后重开目录，恢复最后完整保存的消息、头信息、处理顺序、重试安排
  与已推进时间；已成功消息不会再次投递。末尾未确认的撕裂帧会被截掉，但截
  尾只在开头的版本记录本身完整、CRC 正确且版本受支持时才允许：仅有文件标
  识、标识后只剩一至三个长度字节、长度已写而记录内容或校验缺失、首条记录
  完整但校验错误、首条完整记录不是版本记录、或版本不受支持，都属于已有数
  据损坏，第一次打开即以明确错误拒绝，文件长度与全部字节原样保留，不截短、
  不清空、不补写、不自动替换为新日志，也不返回可继续读写的队列。尚未创建
  `queue.log` 的目录仍按新队列初始化，与“已有但不完整”的日志区分。其余任何
  损坏或不支持的格式同样以明确错误拒绝打开，绝不清空后继续。
- 旧版本写出的日志把消费关系记成一个 NUL 拼接的 `consumeKey`。这种目录可
  直接打开继续使用（无论是否压缩过）：恢复时逐条用记录自身的
  `(来源链, 目标链, nonce)` 校验旧键，历史成功消息只消费它原本的三个值，
  过去因拼接误判而被记为 `replay` 的记录保持原状态、原因与 ID（不自动重
  投，ID 也不可复用），但碰巧共用旧拼接标识的另一条路径用新 ID 提交后可
  正常投递。旧成功记录若与其消息内容或消费归属不一致，则以明确的损坏错误
  拒绝打开并原样保留数据，不借本次修正接受坏记录。
- 两个进程同时打开同一目录时，只有一个能写入，另一个得到明确的锁定失败；
  持有者退出后目录立即可重新使用。
- 存储写入失败返回明确错误，随后该实例拒绝一切写操作；重新打开目录后，
  未确认的写入不存在，已确认的写入完整保留。

## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
