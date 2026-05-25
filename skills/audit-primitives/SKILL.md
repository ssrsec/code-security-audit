---
name: audit-primitives
description: 安全原语识别格式契约（schema audit-primitive/v1）。在 Phase 2 由 audit-sink-agent / audit-control-agent 在发现"能力片段但单独不构成漏洞"时调用本格式发射记录。不主动调度（由 sink/control 触发）、不参与原语组合推理（→ audit-primchain-agent 在 Phase 5）。
---

# 安全原语识别与发射格式（Phase 2 增强）

## Banned Patterns（零容忍）

- 禁止：把已构成完整漏洞的 finding 同时记为原语（重复记录）。
- 禁止：把完全不可利用的代码记为原语（应丢弃）。
- 禁止：`standalone_severity` 设为 `high` 或 `critical`（原语只能 `none / low / medium`；构成 high 的应直接成为 finding）。
- 禁止：`location.line` 凭猜测填写；无法确认时填 `0` 并将 `confidence` 设为 `suspected`。
- 禁止：`evidence` 字段编造代码片段；必须粘贴 Read 输出。
- 禁止：在本 skill 内直接推导原语组合攻击链（属于 `audit-primchain-agent` 的 Phase 5 职责）。

## 角色

本 skill 定义原语（Primitive）的识别标准与标准化消息格式，供 `audit-sink-agent` 和 `audit-control-agent` 在 Phase 2 并行发射原语记录。**原语 = 不完整的攻击能力片段**：单独不危险，但与其他原语组合后可产生高危攻击路径。

## 什么是原语

| 是否原语 | 判断 |
|---------|------|
| ✅ 是 | 能做某件事，但有约束（路径限制、需认证、只能部分控制） |
| ✅ 是 | 本身无危害，但与其他能力组合后危害放大 |
| ❌ 不是 | 已构成完整漏洞（记为 finding） |
| ❌ 不是 | 完全不可利用 → 丢弃 |

**示例：**

- `Files.write("/tmp/" + userFilename)` → 原语（constrained_write，路径被约束）
- `Runtime.exec(cmd)` 且 cmd 来自用户输入且无过滤 → 漏洞，不是原语
- HTTP url 参数可控但只能访问 `http://` → 原语（constrained_ssrf）

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

每条原语写入 `audit/phase2/primitives_batch{N}.md`：

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

- `location.file` 必须通过 Glob/Read 验证文件实际存在。
- `location.line` 必须来自 Read 输出，无法确认时填 `0` 并将 `confidence` 设为 `suspected`。
- `evidence` 字段直接粘贴 Read 输出的代码片段。

## 输出位置

- **同批次文件**：`audit/phase2/primitives_batch{N}.md`（与 `findings_batch{N}.md` 并列）
- **此批次无原语时**：仍须创建空文件并写入 `> 本批次未发现原语。`（避免 composer-agent 报告文件缺失）
