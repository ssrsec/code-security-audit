# validate worker

## 职责

处理 validation queue，将 candidate/hypothesis finding 转换为 confirmed、hypothesis、rejected 或 deferred。

## 输入

- validation task。
- finding。
- capabilities。
- requests/evidence history。
- live target config。
- assets payload/playbook。

## 输出

- request fragment。
- evidence fragment。
- mutation fragment。
- updated finding status。
- new capability fragment。

## 已实现能力

`validate_worker.py` 提供生产闭环所需的 validation queue 生成：

```bash
python3 workers/validate_worker.py --audit-dir audit-v2
```

输入：

- `audit-v2/findings.jsonl`

输出：

- `audit-v2/validation_queue.jsonl`

已实现把未确认 finding 转为待验证任务，并按风险确定优先级和 L1/L2/L3 安全等级。若 finding 声明 `requiresCapabilities[]`，validate worker 会从 `capabilities.jsonl` 选择 `candidateProviders[]`；缺少 provider 时任务进入 `needs-user-hint` blocker。真实靶场验证必须继续写入 request/evidence/mutation 并通过质量门；没有证据时不得把 V0/V1 升级为 confirmed。

## 流程

1. 查询 required capabilities。
2. 选择 provider。
3. 生成验证计划。
4. 决定 L1/L2/L3。
5. 执行或设计请求。
6. 记录 evidence。
7. 更新 finding/capability。

## L2 要求

L2 必须记录：

- baseline。
- mutation。
- proof。
- cleanup。
- post-cleanup assert。

## 禁止

- 不把靶场 404 当作白盒不成立。
- 不用 `同上`、`上一步`、`REPLACE`。
- 不自动脱敏证据。
- 不用 hypothesis capability 确认 confirmed finding。
- 不执行未批准 L3。
