# Failure Recovery Protocol

## 原则

失败必须结构化记录，可恢复失败不得丢弃进度，不可恢复失败必须明确阻塞原因。

## 失败分类

| 类型 | 可恢复 | 处理 |
|---|---|---|
| worker timeout | 是 | release claim, retry or split task |
| malformed fragment | 是 | schema gate error, retry worker |
| live target down | 是 | pause V4, continue static/local |
| partial deploy | 是 | mark environment blocker |
| missing service/table/logicflow | 是 | preserve whitebox conclusion |
| tool unavailable | 视情况 | fallback or blocker |
| decompile failure | 需授权 | request approval for downgrade |
| L3 approval missing | 否 | block |
| scope unclear | 否 | block |

## 失败事件

每个失败写入 event：

```json
{
  "eventType": "failure",
  "severity": "blocker | error | warning",
  "component": "worker | live-target | quality | tooling",
  "objectRef": "",
  "message": "",
  "recoverable": true,
  "nextAction": ""
}
```

## 重试

重试必须有变化：

- 更小任务。
- 更明确输入。
- 新能力 provider。
- 靶场恢复。
- 工具可用。

禁止无变化重复执行同一失败动作。

## 部分结果

worker 部分成功时：

- 保留已通过 Schema Gate 的 fragment。
- 标记失败 fragment。
- 不让失败覆盖成功结果。

## 补丁报告

补验成功后：

- 不覆盖原报告版本。
- 更新 report_model。
- 生成 patch report。
- 记录补验事件。
