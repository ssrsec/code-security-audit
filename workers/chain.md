# chain worker

## 职责

构建 attack graph，统一处理漏洞组合和 capability chain。

## 输入

- findings。
- capabilities。
- evidence。
- assets attack-chain catalog。

## 输出

- attack-chain fragment。
- attack graph update。

## 已实现能力

`chain_worker.py` 基于显式 capability 依赖生成 attack chain：

```bash
python3 workers/chain_worker.py --audit-dir audit-v2
```

输入：

- `audit-v2/findings.jsonl`
- `audit-v2/capabilities.jsonl`

输出：

- `audit-v2/attack_chains.jsonl`
- `audit-v2/attack_graph.json`

只有 `finding.requiresCapabilities[]` 明确引用已存在 capability 时才会建链。若 provider capability 或 consumer finding 仍是 hypothesis/candidate，链也只能是 hypothesis。

## 组合条件

每条链必须说明：

- A 的输出如何成为 B 的输入。
- 哪个前置条件被降低。
- 哪个影响被放大。
- 哪个能力被解锁。

## Value Increase

允许：

- `reduces-preconditions`
- `increases-impact`
- `improves-reliability`
- `bypasses-network`
- `bypasses-auth`
- `enables-followup`

## 禁止

- 不因两个漏洞同时存在就组成链。
- 不要求组合后 CVSS 必须高于最高单漏洞。
- 不使用不存在的 capability。
- 不把自然语言猜测写为 confirmed chain。
