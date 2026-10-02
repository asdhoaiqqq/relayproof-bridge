# 跨链消息与轻客户端验证服务

## 用途

轻客户端头同步、消息封装与投递、重放防护、中继重试与超时、储备与状态证明校验、跨链可观测。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `relayproof/`，命令入口位于 `cmd/relayproof/`。

```bash
go run ./cmd/relayproof demo
go run ./cmd/relayproof version
go test ./...
```

## 日志规范化（normalize）

`normalize` 子命令从标准输入逐行读取 JSON 日志，在标准输出逐行给出规范化结果，便于检测规则统一读取不同来源的日志。

```bash
go run ./cmd/relayproof normalize < logs.jsonl
```

每行输入必须是一个 JSON 对象，输出一行 JSON 结果：

- 成功：`{"line":行号,"ok":true,"event":{...}}`
- 失败：`{"line":行号,"ok":false,"error":"原因"}`，失败时不输出部分事件，错误原因会指出对应的标准字段。

事件统一使用 `timestamp`、`source_ip`、`action` 三个字段，分别接受别名 `time`、`src_ip`、`event_type`：

- `timestamp` 与 `action` 必填，`source_ip` 可缺省（缺省时不写入事件）。
- 时间为带时区且最多九位小数的 RFC3339 字符串，统一转成 UTC 后以 RFC3339Nano 格式输出。
- `action` 为字符串，去除首尾空白后不能为空。
- `source_ip` 若提供必须是合法的 IPv4 或 IPv6 地址（不带端口），同一地址的不同写法（如 `2001:0db8::1` 与 `2001:db8::1`）输出相同的规范结果。
- 字段值为 `null` 或类型不符时该条失败，不按缺省处理。
- 标准名与别名同时出现时，两个值分别规范化后比较：一致则合并，不一致则整条失败。所有候选值都必须合法。
- 顶层 JSON 键重复时该条失败（即使值相同）。
- 未参与映射的字段原样放入事件的 `extra` 对象（保留 JSON 值与嵌套结构）；输入自带的 `extra` 作为普通附加字段保留，不与输出容器合并。

空白行不产生结果，但仍计入物理行号。单行失败不影响后续日志；存在任何失败时进程以非零状态退出，全部有效或输入为空时正常退出。输出确定性，不读取当前时间、不生成随机标识。

## 技术方向

bridge, light-client, relayer, message-passing, state-proof, crosschain-monitoring, interchain

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
