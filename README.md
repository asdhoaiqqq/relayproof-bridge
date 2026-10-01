# 跨链消息与轻客户端验证服务

## 用途

轻客户端头同步、消息封装与投递、重放防护、中继重试与超时、储备与状态证明校验、跨链可观测。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `relayproof/`，命令入口位于 `cmd/relayproof/`。

```bash
go run ./cmd/relayproof demo
go run ./cmd/relayproof version
go test ./...
```

## 持久化本地消息队列

队列状态保存在用户指定的状态目录中，仅使用标准库与本地数据。投递成功表示消息进入本地成功记录，并同时消费该来源链、目标链与 nonce 的组合，无须连接真实链或收件服务。

```bash
# 登记来源链及其头信息（可信、高度覆盖证明高度时才可能投递成功）
go run ./cmd/relayproof header --dir /tmp/relayproof-state \
  --chain chain-a --height 200 --root 0xabc --trusted

# 提交消息（绝对过期时刻为 Unix 毫秒）
go run ./cmd/relayproof submit --dir /tmp/relayproof-state \
  --id m1 --from chain-a --to chain-b --nonce 1 \
  --proof-at 100 --expire-at 100000 --payload hello

# 推进处理时间（Unix 毫秒；可重复推进相同时间，倒退被拒绝）
go run ./cmd/relayproof advance --dir /tmp/relayproof-state --time 1000

# 查询单条记录（原消息、状态、原因、下次重试时间）
go run ./cmd/relayproof query --dir /tmp/relayproof-state --id m1

# 列出全部记录（按首次提交顺序）
go run ./cmd/relayproof list --dir /tmp/relayproof-state
```

状态包括：`pending`（待处理）、`waiting_header`（等待可信头）、`success`（成功）、`replay`（重放）、`expired`（超时）、`unknown_source`（未知来源）。

语义要点：

- 同一 ID、相同内容重复提交返回已有记录，不增加队列项；内容不同则返回冲突，原记录不变。
- 不同 ID 可使用相同 nonce 组合，但最多一条成功，其余在处理时记为重放；重放与过期同时满足时按重放处理。
- 新消息在下一次推进时接受首次处理；到期包含恰好等于过期时刻。
- 来源未登记时永久拒绝（未知来源）；已登记但头不可信或高度不足时等待，不消费 nonce。
- 等待消息的重试间隔依次为 1、2、4 秒，翻倍至 60 秒封顶，从实际处理时间计算；跨过多轮间隔也只处理一次。更新头信息不绕过重试时间。
- 状态原子保存：成功记录与 nonce 消费在同一文件替换中生效。重启后恢复最后完整保存的消息、头信息、处理顺序、重试安排与已推进时间，已成功消息不会再次投递。
- 跨进程互斥：同一目录同时只能有一个进程接受写入，另一个立即失败；前者退出后目录可重新使用。
- 损坏或不支持的状态格式会被拒绝打开，不会清空后继续。

## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
