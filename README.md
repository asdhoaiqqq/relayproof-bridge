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

# 由用户提供处理时间（Unix 毫秒）推进；相同时间可重复推进，倒退被拒绝；
# results 按发生顺序列出本次推进内的处理结果，同一消息可能出现多条
$BIN queue advance --state $DIR --now 1700000000000

# 查询：原消息、状态、具体原因、下次重试时间
$BIN queue query --state $DIR --id m1
$BIN queue query --state $DIR
```

### 推进结果（results）与消息当前状态（query）

`advance` 输出的 `results` 按发生顺序保留**本次推进**内的每一条处理结果：
一条消息在同一次推进中被处理多次时，会相应出现多条记录（例如先进入等待，
随后在同一次推进末尾的重放/过期复查中被终结）。`query` 返回的则是消息的
**当前**状态——单个状态快照，不保留历史。因此 results 中的 `waiting` 条目
只表示“本次推进中曾有一次处理进入等待”，并不保证推进结束后它仍在等待；
推进结束后的状态、尝试次数与重试安排一律以 `query` 为准。本文示例中的时间
均为用户提供的 Unix 毫秒处理时间，`--expires-at 0` 表示不过期。

### 头信息与可信覆盖范围

`header` 按**来源链分别**保存头信息：每条链各自维护“最近保存的头”（任意
可信度）与“已接受的最高可信头”。一条消息能否投递，只取决于其来源链已接受
的**最高可信头**是否覆盖它的证明高度，与头的保存先后、最近一次保存了什么
都无关；一条链的头也永远不会覆盖另一条链上的消息。

- 首个 `--trusted` 头**建立**该链的可信覆盖范围：证明高度不超过该可信高度
  的消息才可投递。
- 更高的可信头**扩大**覆盖范围。投递成功原因中写出的高度是投递时实际采用
  的可信高度，既不是消息自己的证明高度，也不是最近保存的头（例如最高可信
  头在 100 时，证明高度 90 的消息成功原因仍写 “trusted header at height
  100”）。
- 较低的可信头、以及任意高度的不可信头（不带 `--trusted`，即使高度更高）
  都可以正常保存，但不会降低已建立的可信高度，也不能用更高的不可信头放行
  超出覆盖范围的消息。
- **保存头信息不等于登记来源链**。没有 `register-source` 的链即使保存了可
  信头，来自它的消息仍按既有未知来源规则终结为 `unknown-source`。
- 写头只更新覆盖范围，本身不处理任何消息，不改变等待消息的尝试次数与已安
  排的下次重试时刻，也不绕过退避等待；消息要等到下一次重试到期、再次处理
  时才按新的覆盖范围判断。因此等待记录查询到的原因是上一次处理时写下的，
  其中的 “current N” 可能暂时落后于刚写入的可信头，下一次到期处理后才会
  刷新。

#### 同高度更新：接受、幂等与头冲突

新提交的**可信头**与该链当前最高可信头**同高度**时：

- 根相同：正常接受（幂等，可重复提交）；
- 根不同：返回可信头冲突 `ErrHeaderConflict`，命令行打印明确错误并以退出码
  **16** 结束；**原可信头继续有效，队列仍可正常使用**。

根按提交的**原字符串逐字节比较**，空根也是合法输入（省略 `--root` 即空
根）：两个同为空根的提交正常接受，空根与非空根互为冲突。

以下两种根差异**不属于**同高冲突，均正常保存：

- 同高度但**不可信**的头根不同——照常保存，不改变可信覆盖范围；
- **较低**可信头的根不同——它不是当前最高可信头，不构成冲突。

注意与消息内容冲突区分：复用同一消息 ID 但内容不同返回的是
`ErrConflict`、退出码 **13**；退出码 **16** 专指头冲突，原消息记录不受
影响。

### 连续示例：更新头后哪条消息先投递

下例使用用户指定的处理时间（Unix 毫秒），可在全新临时目录中原样复现。
初始可信高度为 100，随后保存一个高度 120 的**不可信**头：

```text
$ BIN=./relayproof                 # 或 go run ./cmd/relayproof
$ DIR=$(mktemp -d)
$ $BIN queue register-source --state $DIR --chain chain-a
registered source chain chain-a
$ $BIN queue header --state $DIR --chain chain-a --height 100 --root 0x100 --trusted
stored header chain=chain-a height=100 trusted=true
$ $BIN queue header --state $DIR --chain chain-a --height 120 --root 0x120
stored header chain=chain-a height=120 trusted=false
```

提交证明高度分别为 90 和 110 的两条消息，并在 1700000000000 首次推进：

```text
$ $BIN queue submit --state $DIR --id m90 --from chain-a --to chain-b \
    --nonce 7 --proof-at 90 --payload hello --expires-at 9000000000000
{"id":"m90","status":"pending","reason":"awaiting first processing","attempts":0,"expiresAtMs":9000000000000}
$ $BIN queue submit --state $DIR --id m110 --from chain-a --to chain-b \
    --nonce 8 --proof-at 110 --payload world --expires-at 9000000000000
{"id":"m110","status":"pending","reason":"awaiting first processing","attempts":0,"expiresAtMs":9000000000000}
$ $BIN queue advance --state $DIR --now 1700000000000
{"nowMs":1700000000000,"results":[{"id":"m90","status":"success","reason":"delivered; proof verified by trusted header at height 100"},{"id":"m110","status":"waiting","reason":"waiting for trusted header covering height 110 (current 100)"}]}
```

- m90（证明高度 90）被可信头 100 覆盖，立即成功；成功原因引用的是实际采用
  的可信高度 **100**，与最近保存的不可信头 120 无关。
- m110（证明高度 110）没有被任何**可信**头覆盖（不可信的 120 不放行），进
  入等待、不消费 nonce。首次处理在 1700000000000，第一档退避为 1 秒，故
  下次重试时刻为 1700000001000：

```text
$ $BIN queue query --state $DIR --id m110
{"id":"m110","from":"chain-a","to":"chain-b","nonce":8,"payload":"world","proofAtHeight":110,"expiresAtMs":9000000000000,"status":"waiting","reason":"waiting for trusted header covering height 110 (current 100)","attempts":1,"nextRetryMs":1700000001000}
```

在重试到期**之前**写入能覆盖 110 的可信头，然后提前半秒推进：

```text
$ $BIN queue header --state $DIR --chain chain-a --height 120 --root 0x120 --trusted
stored header chain=chain-a height=120 trusted=true
$ $BIN queue advance --state $DIR --now 1700000000500
{"nowMs":1700000000500,"results":null}
$ $BIN queue query --state $DIR --id m110
{"id":"m110","from":"chain-a","to":"chain-b","nonce":8,"payload":"world","proofAtHeight":110,"expiresAtMs":9000000000000,"status":"waiting","reason":"waiting for trusted header covering height 110 (current 100)","attempts":1,"nextRetryMs":1700000001000}
```

写头没有触发处理：1700000000500 早于下次重试 1700000001000，m110 仍是
`waiting`，尝试次数保持 1，下次重试时刻保持 1700000001000，原因也仍是上
次处理时写下的 “current 100”。等到重试时刻再推进，才按新的可信高度重新
判断并成功，成功原因引用实际采用的可信高度 **120**：

```text
$ $BIN queue advance --state $DIR --now 1700000001000
{"nowMs":1700000001000,"results":[{"id":"m110","status":"success","reason":"delivered; proof verified by trusted header at height 120"}]}
```

时间线汇总：`1700000000000` 首次推进 → m90 成功、m110 等待（重试安排在
`1700000001000`）；`1700000000500` 已写入可信头 120 但重试未到期，仍等待；
`1700000001000` 重试到期再推进，m110 成功。

### 连续示例：一次推进内先等待、后重放

本例在全新目录中原样复现：登记来源链 `a`，保存高度 100 的可信头，依次提
交两条发往 `b`、nonce 同为 7 的消息 `early`（证明高度 101）和 `later`（证
明高度 100）；两条消息都不过期（`--expires-at 0`）。然后在处理时间 1000
推进一次：

```text
$ BIN=./relayproof                 # 或 go run ./cmd/relayproof
$ DIR=$(mktemp -d)
$ $BIN queue register-source --state $DIR --chain a
registered source chain a
$ $BIN queue header --state $DIR --chain a --height 100 --root 0x100 --trusted
stored header chain=a height=100 trusted=true
$ $BIN queue submit --state $DIR --id early --from a --to b \
    --nonce 7 --proof-at 101 --payload early --expires-at 0
{"id":"early","status":"pending","reason":"awaiting first processing","attempts":0}
$ $BIN queue submit --state $DIR --id later --from a --to b \
    --nonce 7 --proof-at 100 --payload later --expires-at 0
{"id":"later","status":"pending","reason":"awaiting first processing","attempts":0}
$ $BIN queue advance --state $DIR --now 1000
{"nowMs":1000,"results":[{"id":"early","status":"waiting","reason":"waiting for trusted header covering height 101 (current 100)"},{"id":"later","status":"success","reason":"delivered; proof verified by trusted header at height 100"},{"id":"early","status":"replay","reason":"nonce combination already consumed by message later"}]}
```

`results` 按发生顺序完整记录了这一次推进的处理过程：

1. **early 等待**：early 先提交、先处理，但它的证明高度 101 没有被可信头
   100 覆盖，进入等待并安排退避重试，**不消费 nonce**——等待中的消息不会
   替自己、也不会替别人占用 nonce。
2. **later 成功**：later 的证明高度 100 被可信头 100 覆盖，投递成功并消费
   `(a, b, 7)`。成功原因引用的是投递时实际采用的可信头高度 **100**。
3. **early 判为重放**：每次推进末尾都会对所有未终结消息复查重放与过期，刚
   刚安排的退避不能屏蔽这次复查。later 已经消费了 nonce，early 随即在同一
   次推进中终结为 `replay`，原因指向真正成功的消息 **later**。

所以消费 nonce 的是 later：**先提交只决定先处理，不决定谁先消费 nonce**；
nonce 只在真正投递成功时才被消费。

推进结束后分别查询，看到的是两条消息各自的当前状态：

```text
$ $BIN queue query --state $DIR --id early
{"id":"early","from":"a","to":"b","nonce":7,"payload":"early","proofAtHeight":101,"status":"replay","reason":"nonce combination already consumed by message later","attempts":2}
$ $BIN queue query --state $DIR --id later
{"id":"later","from":"a","to":"b","nonce":7,"payload":"later","proofAtHeight":100,"status":"success","reason":"delivered; proof verified by trusted header at height 100","attempts":1}
```

- early 的当前状态是 `replay`、尝试次数为 **2**、已没有下次重试时间。它在
  本次推进中经历了两次处理（第一次等待、第二次重放），所以 `results` 里它
  的两条记录都应保留；其中的 waiting 条目不表示推进结束后仍在等待。第一
  次处理（时间 1000，第一档退避 1 秒）曾把重试安排在 **2000**，但随后的
  重放终结了这条消息，该安排随之取消——查询结果不再含 `nextRetryMs`。查
  询仍返回原消息的内容（`a → b`、nonce 7、payload `early`、证明高度 101）
  与最终原因（指向 later）。
- later 的当前状态是 `success`、尝试次数为 **1**、也没有下次重试时间。

#### 边界：两条都未覆盖时，相同 nonce 不会判重放

若最初保存的是高度 **99** 的可信头，则 early（证明高度 101）和 later（证
明高度 100）都不满足覆盖条件。推进后两条各自等待、各有一次尝试并分别安排
重试，nonce 仍未被任何消息消费，**不会仅因 nonce 相同就判其中一条重放**：

```text
$ D2=$(mktemp -d)
$ $BIN queue register-source --state $D2 --chain a
registered source chain a
$ $BIN queue header --state $D2 --chain a --height 99 --root 0x99 --trusted
stored header chain=a height=99 trusted=true
$ $BIN queue submit --state $D2 --id early --from a --to b \
    --nonce 7 --proof-at 101 --payload early --expires-at 0
{"id":"early","status":"pending","reason":"awaiting first processing","attempts":0}
$ $BIN queue submit --state $D2 --id later --from a --to b \
    --nonce 7 --proof-at 100 --payload later --expires-at 0
{"id":"later","status":"pending","reason":"awaiting first processing","attempts":0}
$ $BIN queue advance --state $D2 --now 1000
{"nowMs":1000,"results":[{"id":"early","status":"waiting","reason":"waiting for trusted header covering height 101 (current 99)"},{"id":"later","status":"waiting","reason":"waiting for trusted header covering height 100 (current 99)"}]}
$ $BIN queue query --state $D2 --id early
{"id":"early","from":"a","to":"b","nonce":7,"payload":"early","proofAtHeight":101,"status":"waiting","reason":"waiting for trusted header covering height 101 (current 99)","attempts":1,"nextRetryMs":2000}
$ $BIN queue query --state $D2 --id later
{"id":"later","from":"a","to":"b","nonce":7,"payload":"later","proofAtHeight":100,"status":"waiting","reason":"waiting for trusted header covering height 100 (current 99)","attempts":1,"nextRetryMs":2000}
```

相同 nonce 在提交时并不互斥；只有当其中一条先被可信头覆盖、真正投递成功
并消费 nonce 后，其余消息才会在处理时记为 `replay`。

### 连续示例：同高度头冲突的边界

在另一个全新目录中，当前最高可信头为高度 100、根 `0x100`。同高度同根正常
接受；同高度异根的可信头返回冲突、退出码 16：

```text
$ D2=$(mktemp -d)
$ $BIN queue register-source --state $D2 --chain chain-a
registered source chain chain-a
$ $BIN queue header --state $D2 --chain chain-a --height 100 --root 0x100 --trusted
stored header chain=chain-a height=100 trusted=true
$ $BIN queue header --state $D2 --chain chain-a --height 100 --root 0x100 --trusted; echo "exit=$?"
stored header chain=chain-a height=100 trusted=true
exit=0
$ $BIN queue header --state $D2 --chain chain-a --height 100 --root 0xdead --trusted; echo "exit=$?"
error: trusted header conflict: different root at the accepted height: chain "chain-a" height 100: submitted root "0xdead" conflicts with accepted root "0x100"
exit=16
```

冲突后原可信头继续有效，队列照常可用：

```text
$ $BIN queue submit --state $D2 --id c1 --from chain-a --to chain-b \
    --nonce 1 --proof-at 100 --payload x --expires-at 9000000000000
{"id":"c1","status":"pending","reason":"awaiting first processing","attempts":0,"expiresAtMs":9000000000000}
$ $BIN queue advance --state $D2 --now 1700000000000
{"nowMs":1700000000000,"results":[{"id":"c1","status":"success","reason":"delivered; proof verified by trusted header at height 100"}]}
```

同高度异根的**不可信**头、以及异根的**较低**可信头都正常保存（退出码
0），且可信覆盖范围仍是 100——证明高度 101 的消息继续等待：

```text
$ $BIN queue header --state $D2 --chain chain-a --height 100 --root 0xfeed; echo "exit=$?"
stored header chain=chain-a height=100 trusted=false
exit=0
$ $BIN queue header --state $D2 --chain chain-a --height 50 --root 0x50 --trusted; echo "exit=$?"
stored header chain=chain-a height=50 trusted=true
exit=0
$ $BIN queue submit --state $D2 --id c2 --from chain-a --to chain-b \
    --nonce 2 --proof-at 101 --payload y --expires-at 9000000000000
{"id":"c2","status":"pending","reason":"awaiting first processing","attempts":0,"expiresAtMs":9000000000000}
$ $BIN queue advance --state $D2 --now 1700000100000
{"nowMs":1700000100000,"results":[{"id":"c2","status":"waiting","reason":"waiting for trusted header covering height 101 (current 100)"}]}
```

作为对照，对仍在等待的 c2 用同一 ID 提交不同内容，是**消息内容**冲突（退
出码 13），与头冲突（16）是两类错误：

```text
$ $BIN queue submit --state $D2 --id c2 --from chain-a --to chain-b \
    --nonce 2 --proof-at 101 --payload CHANGED; echo "exit=$?"
error: message id conflict: existing record has different content: message c2
exit=13
```

空根按原字符串参与比较：两个空根提交幂等接受，空根与非空根同高相遇仍是头
冲突（错误信息中会回显 accepted root ""）：

```text
$ D3=$(mktemp -d)
$ $BIN queue register-source --state $D3 --chain x
registered source chain x
$ $BIN queue header --state $D3 --chain x --height 1 --root "" --trusted
stored header chain=x height=1 trusted=true
$ $BIN queue header --state $D3 --chain x --height 1 --root "" --trusted; echo "exit=$?"
stored header chain=x height=1 trusted=true
exit=0
$ $BIN queue header --state $D3 --chain x --height 1 --root other --trusted; echo "exit=$?"
error: trusted header conflict: different root at the accepted height: chain "x" height 1: submitted root "other" conflicts with accepted root ""
exit=16
```

保存头不等于登记来源：只给未登记的链保存可信头，来自它的消息在推进时仍终
结为 `unknown-source`：

```text
$ D4=$(mktemp -d)
$ $BIN queue header --state $D4 --chain chain-ghost --height 100 --root 0x1 --trusted
stored header chain=chain-ghost height=100 trusted=true
$ $BIN queue submit --state $D4 --id g1 --from chain-ghost --to chain-b \
    --nonce 1 --proof-at 1 --payload z --expires-at 9000000000000
{"id":"g1","status":"pending","reason":"awaiting first processing","attempts":0,"expiresAtMs":9000000000000}
$ $BIN queue advance --state $D4 --now 1700000000000
{"nowMs":1700000000000,"results":[{"id":"g1","status":"unknown-source","reason":"unknown source chain chain-ghost"}]}
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
  随后对所有未终结消息重新检查重放与过期；两者同时满足时按重放处理。因此
  同一条消息可能在一次推进的 `results` 中出现多条（如先等待、随后被重放
  终结），两条记录都保留；`results` 是本次处理过程的顺序记录，消息推进后
  的最终状态、尝试次数与重试安排以 `query` 为准。
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
- 消息 ID 按调用方给出的原始字节逐字落盘并逐字节比较：Go 接口允许任何非空
  字符串，包括中文、空白、冒号、NUL 字节以及与无效 UTF-8 字节混合的文字。
  合法 UTF-8 的 ID 继续使用历史的普通 `id` 字段（命令行文本参数与 JSON 输出
  因此保持兼容）；含无效字节的 ID 若直接交给 JSON 编码会被静默改写成
  U+FFFD，使多个原本不同的 ID 在重开后合并成无法打开的重复记录，因此改写
  为 `idB64` 以 base64 保存原始字节，成功记录的消费归属对应使用
  `consumeByB64`；重放原因中嵌入的成功消息 ID 同理使用 `reasonB64`。于是
  单字节 `0xFF`、单字节 `0xFE` 与合法字符 U+FFFD 始终是三个不同的 ID，提交
  确认成功后该标识在提交返回、单条查询、全部查询、推进结果、重开目录与自动
  压缩保存中都逐字节对应同一条消息。旧版本已保存成普通文字（含已被改写成
  U+FFFD）的 ID 仍按字面原意读取，不猜测曾经丢失的字节；同一记录同时携带
  `id` 与 `idB64`（或 `reason`/`reasonB64`、`consumeBy`/`consumeByB64`
  两者）、或 base64 无法解码，都属于任何版本都不会写出的损坏记录，打开时以
  明确错误拒绝并原样保留文件。
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
