# reviewer worker

## 职责

审查结构化产物和质量门结果，提出阻塞项与修正建议。

## 输入

- SQLite 导出的结构化数据。
- quality results。
- EMS regression results。
- rendered reports。

## 输出

- reviewer notes。
- quality issue explanation。
- recommended next actions。

## 已实现能力

`reviewer_worker.py` 审查结构化产物和质量门结果：

```bash
python3 workers/reviewer_worker.py \
  --audit-dir audit-v2 \
  --quality-result audit-v2/quality-result.json
```

输出：

- `audit-v2/reviewer_notes.json`

reviewer 只给出 blocker/error/warning 和交付决策，不修改 finding、evidence、capability、chain 或 report model。

## 原则

- reviewer 不直接修改事实。
- reviewer 不降级 blocker。
- reviewer 不能用自然语言覆盖 quality gate。

## 必查

- Schema Gate 是否通过。
- Semantic Gate 是否通过。
- PoC Gate 是否通过。
- Render Gate 是否通过。
- Regression Gate 是否通过。
- 是否存在自动脱敏。
- 是否存在 L2 无 cleanup。
- compiled-only/mixed 项目是否存在缺失或未完成反编译任务。

## 禁止

- 不替 worker 补 evidence。
- 不把 warning 当 blocker。
- 不把 blocker 当 warning。
- 不跳过 EMS 回归。
