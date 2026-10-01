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
- 每次推进先按首次提交顺序处理到期消息（新消息在下一次推进时首次处理），
  随后对所有未终结消息重新检查重放与过期；两者同时满足时按重放处理。
- 来源已登记但头不可信或高度不足时保持等待、不消费 nonce；更新头信息不
  绕过重试时间。等待重试间隔依次为 1、2、4、8、16、32 秒，之后 60 秒封顶，
  从实际处理时间计算；一次推进跨过多个间隔也只处理一次。
- 待处理（未首次处理）与终结记录没有下次重试时间。

### 持久化与故障恢复

- 状态写入目录下的 `queue.log`：仅追加、帧带 CRC32 校验、每条记录 fsync
  后才确认成功；成功记录与 nonce 消费是同一条日志，不可能各自单独生效。
- 突然退出后重开目录，恢复最后完整保存的消息、头信息、处理顺序、重试安排
  与已推进时间；已成功消息不会再次投递。末尾未确认的撕裂帧会被截掉，其余
  任何损坏或不支持的格式都以明确错误拒绝打开，绝不清空后继续。
- 两个进程同时打开同一目录时，只有一个能写入，另一个得到明确的锁定失败；
  持有者退出后目录立即可重新使用。
- 存储写入失败返回明确错误，随后该实例拒绝一切写操作；重新打开目录后，
  未确认的写入不存在，已确认的写入完整保留。

## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
