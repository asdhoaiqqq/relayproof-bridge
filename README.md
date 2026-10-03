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
- 每行输出 `{"line":行号,"ok":true,"event":...}` 或
  `{"line":行号,"ok":false,"error":"..."}`；空白行不产生输出但计入行号。
  存在失败行时继续处理后续日志，并以非零状态退出。


## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
