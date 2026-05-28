# report worker

## 职责

从 `report_model` 渲染内部完整证据报告和补丁报告。

## 输入

- report model。
- findings。
- evidence。
- capabilities。
- attack chains。
- quality results。

## 输出

- rendered report files。
- render events。

## 已实现能力

`report_worker.py` 从结构化产物生成 `report_model.json`：

```bash
python3 workers/report_worker.py --audit-dir audit-v2
```

输入：

- `audit-v2/project.json`
- `audit-v2/attack_surface.json`
- `audit-v2/findings.jsonl`
- `audit-v2/attack_chains.jsonl`
- `audit-v2/validation_queue.jsonl`

输出：

- `audit-v2/report_model.json`

报告渲染继续由 `report/render_report.py` 执行。`report_worker.py` 只纳入 confirmed/reported/patched findings；candidate、hypothesis、deferred 只能进入 limitations 或验证队列，不得进入漏洞详情。

如果存在未完成反编译任务，report model 必须在 limitations 中披露，不得把 compiled-only 覆盖缺口隐藏为完整审计。

## 原则

- 不新增漏洞。
- 不修改 evidence。
- 不自动脱敏。
- 不从 Markdown 反解析事实。
- 报告必须引用结构化 ID。

## 禁止

- 不直接读取 legacy `validated_findings.md` 生成最终报告。
- 不把缺证据 finding 写成 confirmed。
- 不隐藏 L2 cleanup failure。
- 不用链接替代关键复现内容。
