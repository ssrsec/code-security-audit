---
name: audit-primitives
description: 安全原语识别与发射技能。在 Phase 2 审计（Sink-driven 或 Control-driven）过程中，当发现单独不构成漏洞但具有可被组合利用的能力片段时，必须使用此 skill 的规范格式记录原语。典型场景：发现受限文件写（路径被约束）、可控 SSRF（仅能访问部分内网）、受限读（路径前缀固定）、可预测 Token（需配合其他漏洞）等单独低危或无危害的能力片段。即使该原语 standalone_severity 为 none，也必须记录——原语的价值在于组合。所有由 audit-sink-agent 或 audit-control-agent 在 Phase 2 中发现的能力片段都应调用此格式发射。
---

# 安全原语识别与发射（Phase 2 增强）

## 角色

本 skill 定义了原语（Primitive）的识别标准和标准化消息格式，供 `audit-sink-agent` 和 `audit-control-agent` 在 Phase 2 审计中并行发射原语记录。**原语不是漏洞，是"不完整的攻击能力片段"**。单独不危险，但多个原语组合后可产生高危攻击路径。

## 什么是原语

原语是代码中发现的、攻击者可利用但单独不足以构成漏洞的**能力片段**。判断标准：

- **是原语**：能做某件事，但有约束（路径限制、需认证、只能部分控制）
- **是原语**：本身无危害，但与其他能力组合后危害放大
- **不是原语**：已经构成完整漏洞的（记为 finding，不记为原语）
- **不是原语**：完全不可利用的代码（丢弃）

**示例判断：**
- `Files.write("/tmp/" + userFilename)` → 原语（constrained_write，路径被约束）
- `Runtime.exec(cmd)` 且 cmd 来自用户输入且无过滤 → 漏洞，不是原语
- `HTTP 请求 url 参数可控但只能访问 http://` → 原语（constrained_ssrf）

## capability 枚举（必须使用以下值）

```
READ     → unconstrained_read / constrained_read / reflected_read
WRITE    → arbitrary_write / constrained_write / append_only
EXEC     → os_command / script_eval / deserialization_exec / scheduled_exec
AUTH     → authn_bypass / authz_bypass / token_forgery / session_fixation
REDIRECT → ssrf / open_redirect / dns_rebind
INJECT   → sql_injection / template_injection / expression_injection / prototype_pollution
LEAK     → credential_leak / path_disclosure / source_disclosure / timing_oracle
CONTROL  → race_condition / state_manipulation / logic_bypass
```

## 标准消息格式（audit-primitive/v1）

每条原语写入 `audit/phase2/primitives_batch{N}.md`，使用以下格式：

````markdown
### prim-NNN

```json
{
  "schema": "audit-primitive/v1",
  "primitive_id": "prim-001",
  "discovered_by": "audit-sink-agent",
  "batch": 1,

  "capability": "constrained_write",
  "subtype": "file_write",
  "controllability": "partial",

  "constraints": [
    "写入路径前缀必须为 /tmp/",
    "文件名后缀由用户控制",
    "需要有效 session token"
  ],

  "can_unlock": [
    "cron_hijack",
    "log_poisoning",
    "path_traversal_to_arbitrary_write"
  ],

  "location": {
    "file": "FileUploadController.java",
    "line": 88,
    "method": "uploadTempFile",
    "call_chain": "FileUploadController.java:88 → FileService.java:42 → Files.write:7"
  },

  "evidence": "Files.write(Paths.get(\"/tmp/\" + userFilename), content)",

  "standalone_severity": "none",
  "confidence": "confirmed",
  "tags": ["filesystem", "write", "partial-path-control", "post-auth"]
}
```
````

## 字段填写规范

| 字段 | 约束 |
|------|------|
| `primitive_id` | 格式 `prim-NNN`，跨批次全局递增，不按批次重置 |
| `controllability` | `full`（攻击者完全控制）/ `partial`（部分控制）/ `limited`（极少控制） |
| `constraints` | 列出所有限制该原语能力的条件，越具体越好；无约束填 `[]` |
| `can_unlock` | 该原语能够解锁的组合键，参考 `shared/primitive_chain_catalog.md` 中规则的 `constraint_unlock_key` 字段 |
| `evidence` | **必须来自 Read 工具实际输出**，不得编造；单行或短片段即可 |
| `standalone_severity` | `none`（单独无危害）/ `low` / `medium`；原语不产出 high/critical |
| `confidence` | `confirmed`（调用链完整）/ `suspected`（调用链部分不确定）|

## 反幻觉规则（同漏洞发现）

- `location.file` 必须通过 Glob/Read 验证文件实际存在
- `location.line` 必须来自 Read 输出，无法确认时填 `0` 并将 confidence 设为 suspected
- `evidence` 字段直接粘贴 Read 输出的代码片段

## 输出位置

- **同批次文件**：`audit/phase2/primitives_batch{N}.md`（与 findings_batch{N}.md 并列）
- **此批次无原语时**：仍须创建空文件，写入 `> 本批次未发现原语。` 以避免 composer-agent 报告文件缺失
