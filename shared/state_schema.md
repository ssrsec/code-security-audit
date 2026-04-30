# 审计状态与 finding 生命周期

长审计任务不得依赖 LLM 记忆。阶段切换、批次恢复、finding 编号和阻塞项必须写入 `audit/state.json`。

## 1. 状态文件

`audit/state.json` 是断点恢复的唯一状态入口：

```json
{
  "currentPhase": "phase0 | phase1 | phase2 | phase3 | phase4 | phase5 | phase6 | completed",
  "currentBatch": 1,
  "nextFindingId": "vul-001",
  "projectRoot": "",
  "auditStartedAt": "",
  "coverage": {
    "fileEnumeration": "0/0",
    "staticScan": "0/0",
    "highRiskDeepRead": "0/0"
  },
  "artifacts": {
    "inScopeFiles": "audit/phase1/in_scope_files.txt",
    "reviewedPaths": "audit/phase2/reviewed_paths_merged.txt",
    "candidateFindings": "audit/phase2/candidate_findings.json",
    "validatedFindings": "audit/phase4/validated_findings.md"
  },
  "unresolvedQuestions": [],
  "blockedBy": null,
  "lastUpdatedAt": ""
}
```

## 2. 更新时机

必须在以下时机更新 `audit/state.json`：

- 阶段开始和阶段完成时。
- 每个阶段 2 批次开始和完成时。
- 新增、合并、拒绝或验证 finding 时。
- 覆盖率变化时。
- 上下文即将耗尽、工具失败、缺少测试环境或需要用户输入时。

## 3. finding 生命周期

每条 finding 只能沿以下状态流转：

```text
candidate -> challenged -> validated | rejected | deferred -> reported
```

- `candidate`：阶段 2 发现，只有 V0/V1 线索。
- `challenged`：阶段 3 已完成反向审查。
- `validated`：阶段 4 已确认或待验证，具备报告准入字段。
- `rejected`：阶段 4 证明不成立。
- `deferred`：缺少授权环境、账号、外部服务或运行时条件，保留为待验证或残余风险。
- `reported`：阶段 6 已写入最终报告。

## 4. 去重与合并

不同轨道或批次发现相同问题时必须合并，不得重复编号。

去重键：

```text
漏洞类型 + 入口/触发点 + sink 或 control gap + 影响资产
```

合并规则：

- 保留最早的 finding id。
- 合并 Sink-driven 和 Control-driven 的证据链。
- 合并更高验证等级、更多代码证据和更完整修复建议。
- 在 `candidate_findings.json` 中记录 `mergedFrom`。

## 5. 恢复规则

用户说「继续审计」时：

1. 先读取 `audit/state.json`。
2. 再读取 state 中列出的关键产物。
3. 从 `currentPhase` 和 `currentBatch` 继续。
4. 若 state 缺失但 `audit/` 存在，从最近阶段产物重建 state。
