# v2 State Protocol

## 权威存储

v2 使用 SQLite 作为权威状态存储：

```text
audit-v2/state.sqlite
```

同时导出事件流：

```text
audit-v2/events.jsonl
```

`events.jsonl` 用于审计追溯和人工 diff，不作为并发写入权威源。

## 核心对象

SQLite 必须能表达：

- project
- phase
- worker
- intent
- finding
- callchain
- request
- evidence
- capability
- mutation
- validation task
- attack chain
- quality result
- report model version
- hint

## 事件要求

以下动作必须写事件：

- 阶段开始和结束。
- worker claim、heartbeat、release、timeout。
- finding 新增、合并、确认、拒绝、延期、报告。
- capability 新增、消费、撤销。
- request 执行。
- evidence 写入。
- L2 mutation。
- quality gate 执行。
- 靶场异常。
- 用户 Hint。
- 报告渲染。

## ID 约定

| 对象 | 前缀 |
|---|---|
| finding | `vul-` |
| callchain | `cc-` |
| request | `req-` |
| evidence | `ev-` |
| capability | `cap-` |
| mutation | `mut-` |
| validation task | `val-` |
| attack chain | `chain-` |
| quality result | `qr-` |

编号由状态层统一分配，worker 不自行生成最终编号。

## 恢复

恢复流程：

1. 打开 `state.sqlite`。
2. 读取当前 phase、pending intents、open validation tasks。
3. 检查未完成 worker claim 是否超时。
4. 从 events 导出校验最近状态。
5. 继续未完成队列。

## 禁止

- 以 Markdown 文件作为权威状态。
- 多 worker 直接写同一最终文件。
- 删除历史 evidence。
- 覆盖已存在 request/evidence。
- 无事件修改 finding 状态。
