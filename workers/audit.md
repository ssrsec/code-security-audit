# audit worker

## 职责

处理审计 intent，发现候选漏洞、调用链和可复用 capability。

## 输入

- project。
- attack surface。
- coverage tasks。
- assets catalogs。
- 当前 intent。

## 输出

- candidate finding fragment。
- callchain fragment。
- capability fragment。
- coverage event。

## 已实现能力

`audit_worker.py` 提供生产闭环所需的结构化候选生成：

```bash
python3 workers/audit_worker.py \
  --audit-dir audit-v2 \
  --limit 20
```

输入：

- `audit-v2/attack_surface.json`

输出：

- `audit-v2/findings.jsonl`
- `audit-v2/callchains.jsonl`
- `audit-v2/capabilities.jsonl`

已实现从 sink 生成 V0 candidate、callchain 和 hypothesis capability。若 recon 在同文件识别到 entry/source，audit worker 会把 entry/source/sink 写入多跳 callchain，并标记仍需验证证据。

同时已实现 control-driven 候选生成：对 admin/delete/role/permission/export/import/config/user 等敏感入口，在认证/授权状态未知或未要求认证时生成 V0 authz candidate。后续语义审计必须补齐跨文件追踪、资源归属判断、控制点判断和证据归档；没有证据时不得把 V0 直接升级为 confirmed。

## 规则

- 可以同时记录 sink 证据和 control 证据。
- 发现二阶数据流时必须记录 storage boundary。
- 发现 capability 时写 provider/consumer 语义。
- 不做完整 V4 验证，但可记录低成本 triage probe。

## 禁止

- 不直接写最终报告。
- 不直接确认没有 evidence 的漏洞。
- 不因红队模式只找固定枚举类型。
- 不把 LLM 判断写成不可追溯事实。
