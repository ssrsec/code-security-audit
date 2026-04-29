# 安全原语组合系统 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有审计流水线中叠加原语通道，使 Phase 2 Agent 同时输出能力片段（原语），Phase 5 新增 audit-composer-agent 通过规则表+LLM 推导跨原语攻击链，Phase 6 报告新增「原语组合攻击链」小节。

**Architecture:** 原语通道与现有漏洞通道并行流动，互不干扰。audit-validate-agent 零改动。新增 audit-composer-agent 在 Phase 5 与 audit-validate-agent 并行调度。规则表（primitive_chain_catalog.md）提供高置信命中，LLM 开放推理兜底。

**Tech Stack:** Markdown + JSON（原语格式）；Claude Code Agent 系统；现有 audit plugin 目录结构。

---

## 文件变更清单

| 操作 | 文件路径 | 说明 |
|------|---------|------|
| 新建 | `shared/primitive_chain_catalog.md` | 15 条预置规则表 |
| 新建 | `agents/audit-composer-agent.md` | 原语组合 Agent |
| 新建 | `skills/audit-primitives/SKILL.md` | 原语识别指导 skill |
| 修改 | `agents/audit-sink-agent.md` | 追加原语输出章节 |
| 修改 | `agents/audit-control-agent.md` | 追加原语输出章节 |
| 修改 | `skills/audit-sink/SKILL.md` | 追加原语输出指导 |
| 修改 | `skills/audit-control/SKILL.md` | 追加原语输出指导 |
| 修改 | `agents/audit-orchestrator.md` | Phase 5 并行调度变更 |
| 修改 | `agents/audit-report-agent.md` | 新增 4.2 章节逻辑 |
| 修改 | `skills/audit-report/SKILL.md` | 新增 4.2 章节说明 + 清理规则追加 |
| 修改 | `skills/code-security-audit/SKILL.md` | 架构图更新 |
| 修改 | `cursor-plugin/rules/audit-workflow.mdc` | 原语通道说明 |

---

## Task 1：创建原语规则表

**Files:**
- Create: `shared/primitive_chain_catalog.md`

- [ ] **Step 1：新建规则表文件**

写入以下完整内容：

```markdown
# 原语组合规则表（Primitive Chain Catalog）

本规则表供 `audit-composer-agent` 的 Step 2（规则表快速命中）使用。
每条规则定义一个已知的安全原语组合模式，包含所需原语、约束传播逻辑和组合结果。

**规则扩展约定：**
- 新增规则追加 JSON 块，`rule_id` 按 `CHAIN-RULE-NNN` 递增
- `resulting_severity` 只允许 `严重 / 高危 / 中危`（原语组合不产出低危）
- `required_primitives` 含三项时为三跳链，引擎逻辑不变

---

## CHAIN-RULE-001

```json
{
  "rule_id": "CHAIN-RULE-001",
  "name": "受限写 + 定时任务 → 定时代码执行",
  "required_primitives": [
    { "capability": "constrained_write", "constraint_unlock_key": "cron_hijack" },
    { "capability": "scheduled_exec" }
  ],
  "constraint_propagation": "constrained_write 的路径约束须包含 cron 执行目录或通配符路径",
  "resulting_capability": "arbitrary_code_execution",
  "resulting_severity": "高危",
  "attack_narrative": "写入恶意脚本至 cron 可执行路径 → 等待定时触发 → RCE"
}
```

## CHAIN-RULE-002

```json
{
  "rule_id": "CHAIN-RULE-002",
  "name": "受限写 + 路径遍历解锁 → 任意写 Webshell",
  "required_primitives": [
    { "capability": "constrained_write", "constraint_unlock_key": "path_traversal_to_arbitrary_write" },
    { "capability": "constrained_read", "constraint_unlock_key": "path_traversal_to_arbitrary_write" }
  ],
  "constraint_propagation": "constrained_write 的路径前缀约束被路径遍历（../）序列突破",
  "resulting_capability": "arbitrary_write",
  "resulting_severity": "严重",
  "attack_narrative": "通过路径遍历绕过路径约束 → 向 Web 根目录写入 shell 文件 → RCE"
}
```

## CHAIN-RULE-003

```json
{
  "rule_id": "CHAIN-RULE-003",
  "name": "受限读 + 路径泄露解锁 → 任意文件读",
  "required_primitives": [
    { "capability": "constrained_read", "constraint_unlock_key": "path_traversal_to_arbitrary_write" },
    { "capability": "path_disclosure" }
  ],
  "constraint_propagation": "path_disclosure 提供真实路径，constrained_read 的路径约束被遍历序列突破",
  "resulting_capability": "arbitrary_file_read",
  "resulting_severity": "高危",
  "attack_narrative": "通过路径泄露获取真实路径 → 路径遍历绕过约束 → 读取任意文件"
}
```

## CHAIN-RULE-004

```json
{
  "rule_id": "CHAIN-RULE-004",
  "name": "SSRF + 内网反序列化 → 内网 RCE",
  "required_primitives": [
    { "capability": "ssrf" },
    { "capability": "deserialization_exec" }
  ],
  "constraint_propagation": "ssrf 突破网络隔离，使内网只监听 deserialization_exec 端点可达",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "通过 SSRF 访问内网反序列化端点 → 发送 gadget 链 payload → RCE"
}
```

## CHAIN-RULE-005

```json
{
  "rule_id": "CHAIN-RULE-005",
  "name": "SSRF + 云元数据端点 → 凭证窃取",
  "required_primitives": [
    { "capability": "ssrf" },
    { "capability": "credential_leak" }
  ],
  "constraint_propagation": "ssrf 访问 169.254.169.254 或类似元数据端点，获取 IAM 临时凭证",
  "resulting_capability": "credential_theft",
  "resulting_severity": "高危",
  "attack_narrative": "SSRF 请求云元数据地址 → 返回 IAM 密钥 → 横向移动"
}
```

## CHAIN-RULE-006

```json
{
  "rule_id": "CHAIN-RULE-006",
  "name": "SQL 注入 + 文件写权限 → INTO OUTFILE Webshell",
  "required_primitives": [
    { "capability": "sql_injection" },
    { "capability": "arbitrary_write" }
  ],
  "constraint_propagation": "sql_injection 具备 FILE 权限（MySQL），arbitrary_write 指向 Web 可执行目录",
  "resulting_capability": "web_shell",
  "resulting_severity": "严重",
  "attack_narrative": "SQL 注入写入 INTO OUTFILE → Web 根目录生成 shell 文件 → RCE"
}
```

## CHAIN-RULE-007

```json
{
  "rule_id": "CHAIN-RULE-007",
  "name": "Token 伪造 + 授权绕过 → 完全权限提升",
  "required_primitives": [
    { "capability": "token_forgery" },
    { "capability": "authz_bypass" }
  ],
  "constraint_propagation": "token_forgery 提供合法格式的高权限 token，authz_bypass 使该 token 被接受",
  "resulting_capability": "full_privilege_escalation",
  "resulting_severity": "严重",
  "attack_narrative": "伪造管理员 JWT → 绕过授权检查 → 全系统管理权限"
}
```

## CHAIN-RULE-008

```json
{
  "rule_id": "CHAIN-RULE-008",
  "name": "凭证泄露 + 认证绕过 → 账户接管",
  "required_primitives": [
    { "capability": "credential_leak" },
    { "capability": "authn_bypass" }
  ],
  "constraint_propagation": "credential_leak 提供账号密码或 token，authn_bypass 使攻击者以该身份登录",
  "resulting_capability": "account_takeover",
  "resulting_severity": "高危",
  "attack_narrative": "泄露的凭证重放登录接口 → 绕过认证 → 账户接管"
}
```

## CHAIN-RULE-009

```json
{
  "rule_id": "CHAIN-RULE-009",
  "name": "受限写 + 源码泄露 → 配置覆盖行为劫持",
  "required_primitives": [
    { "capability": "constrained_write", "constraint_unlock_key": "config_overwrite" },
    { "capability": "source_disclosure" }
  ],
  "constraint_propagation": "source_disclosure 暴露配置文件路径，constrained_write 覆盖配置影响业务行为",
  "resulting_capability": "behavior_hijack",
  "resulting_severity": "高危",
  "attack_narrative": "源码泄露获取配置路径 → 写入恶意配置 → 劫持应用逻辑"
}
```

## CHAIN-RULE-010

```json
{
  "rule_id": "CHAIN-RULE-010",
  "name": "模板注入 + 沙箱逃逸 → RCE",
  "required_primitives": [
    { "capability": "template_injection" },
    { "capability": "logic_bypass" }
  ],
  "constraint_propagation": "template_injection 在沙箱中执行，logic_bypass 提供逃逸路径（如 class 链、反射）",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "模板注入进入受限沙箱 → 利用逻辑绕过逃逸沙箱 → RCE"
}
```

## CHAIN-RULE-011

```json
{
  "rule_id": "CHAIN-RULE-011",
  "name": "竞态条件 + 授权绕过 → TOCTOU 权限提升",
  "required_primitives": [
    { "capability": "race_condition" },
    { "capability": "authz_bypass" }
  ],
  "constraint_propagation": "race_condition 在权限检查与操作执行之间创造窗口，authz_bypass 利用该窗口绕过检查",
  "resulting_capability": "privilege_escalation",
  "resulting_severity": "高危",
  "attack_narrative": "并发请求在权限检查后、操作执行前修改状态 → 绕过授权检查 → 提权"
}
```

## CHAIN-RULE-012

```json
{
  "rule_id": "CHAIN-RULE-012",
  "name": "原型链污染 + 表达式注入 → RCE",
  "required_primitives": [
    { "capability": "prototype_pollution" },
    { "capability": "expression_injection" }
  ],
  "constraint_propagation": "prototype_pollution 注入恶意属性到 Object 原型，expression_injection 在表达式求值时触发",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "污染 __proto__ 注入 gadget 属性 → 表达式引擎求值时触发代码执行"
}
```

## CHAIN-RULE-013

```json
{
  "rule_id": "CHAIN-RULE-013",
  "name": "开放重定向 + Token 伪造 → OAuth 回调劫持",
  "required_primitives": [
    { "capability": "open_redirect" },
    { "capability": "token_forgery" }
  ],
  "constraint_propagation": "open_redirect 劫持 OAuth 回调 URL，token_forgery 利用截获的授权码伪造 token",
  "resulting_capability": "account_takeover",
  "resulting_severity": "高危",
  "attack_narrative": "构造恶意 redirect_uri → 用户授权后 code 发至攻击者 → 用 code 换取 token → 账户接管"
}
```

## CHAIN-RULE-014

```json
{
  "rule_id": "CHAIN-RULE-014",
  "name": "受限读 + 凭证泄露 → 配置文件读取密钥",
  "required_primitives": [
    { "capability": "constrained_read", "constraint_unlock_key": "path_traversal_to_arbitrary_write" },
    { "capability": "credential_leak" }
  ],
  "constraint_propagation": "constrained_read 通过路径遍历读取配置文件，credential_leak 确认文件中存储明文凭证",
  "resulting_capability": "credential_theft",
  "resulting_severity": "高危",
  "attack_narrative": "路径遍历读取 application.yml/database.conf → 提取数据库/API 密钥"
}
```

## CHAIN-RULE-015

```json
{
  "rule_id": "CHAIN-RULE-015",
  "name": "SSRF + SQL 注入 + 文件写 → 三跳内网写 Shell",
  "required_primitives": [
    { "capability": "ssrf" },
    { "capability": "sql_injection" },
    { "capability": "arbitrary_write" }
  ],
  "constraint_propagation": "ssrf 到达内网 DB 服务，sql_injection 执行 INTO OUTFILE，arbitrary_write 写入 Web 目录",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "SSRF 访问内网 MySQL → SQL 注入执行 INTO OUTFILE → 写入 Webshell → RCE"
}
```
```

- [ ] **Step 2：验证文件已写入**

```bash
ls -la shared/primitive_chain_catalog.md
head -5 shared/primitive_chain_catalog.md
```

预期：文件存在，首行为 `# 原语组合规则表（Primitive Chain Catalog）`

- [ ] **Step 3：Commit**

```bash
git add shared/primitive_chain_catalog.md
git commit -m "feat: add primitive chain catalog with 15 rules"
```

---

## Task 2：创建 audit-primitives skill

**Files:**
- Create: `skills/audit-primitives/SKILL.md`

- [ ] **Step 1：创建 skill 目录和文件**

写入以下完整内容：

````markdown
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
````

- [ ] **Step 2：验证文件**

```bash
ls -la skills/audit-primitives/SKILL.md
```

- [ ] **Step 3：Commit**

```bash
git add skills/audit-primitives/SKILL.md
git commit -m "feat: add audit-primitives skill with primitive message format"
```

---

## Task 3：修改 audit-sink-agent — 追加原语输出章节

**Files:**
- Modify: `agents/audit-sink-agent.md`

- [ ] **Step 1：在文件末尾「## 输出」章节前插入原语发射章节**

在 `agents/audit-sink-agent.md` 的 `## 输出` 章节前插入：

```markdown
## 原语发射（Phase 2 增强）

在审计过程中，对于单独不构成漏洞但具有可组合利用价值的能力片段，**必须**按 `skills/audit-primitives/SKILL.md` 的格式记录原语，写入 `audit/phase2/primitives_batch{N}.md`。

**典型需记录为原语的场景：**
- 文件写入路径被约束（如仅限 `/tmp/`）→ `constrained_write`
- SSRF 仅能访问部分协议或内网段 → `ssrf`（controllability: partial）
- 文件读取有路径前缀限制 → `constrained_read`
- 反序列化入口存在但 Gadget 未确认 → `deserialization_exec`（confidence: suspected）
- 定时任务路径存在通配符 → `scheduled_exec`

**判定原则：**
- 已构成完整漏洞的 → 记录为 finding，不记为原语
- 完全不可利用的 → 丢弃
- 能力存在但有约束、或需要配合其他能力 → 记为原语

**本批次无原语时**：仍须创建 `audit/phase2/primitives_batch{N}.md`，写入 `> 本批次未发现原语。`
```

- [ ] **Step 2：修改 `## 输出` 章节，追加 primitives_batch 说明**

在现有输出说明后追加：
```
候选原语写入 `audit/phase2/primitives_batch{N}.md`，最终由 audit-composer-agent 做组合推导。
```

- [ ] **Step 3：验证修改**

```bash
grep -n "原语发射" agents/audit-sink-agent.md
grep -n "primitives_batch" agents/audit-sink-agent.md
```

预期：两行均有匹配

- [ ] **Step 4：Commit**

```bash
git add agents/audit-sink-agent.md
git commit -m "feat: add primitive emission section to audit-sink-agent"
```

---

## Task 4：修改 audit-control-agent — 追加原语输出章节

**Files:**
- Modify: `agents/audit-control-agent.md`

- [ ] **Step 1：在 `## 输出` 章节前插入原语发射章节**

内容与 Task 3 Step 1 相同，但 `discovered_by` 对应字段为 `audit-control-agent`，典型场景改为：

```markdown
## 原语发射（Phase 2 增强）

在鉴权审计过程中，对于单独不构成漏洞但具有可组合利用价值的控制类原语，**必须**按 `skills/audit-primitives/SKILL.md` 的格式记录，写入 `audit/phase2/primitives_batch{N}.md`。

**典型需记录为原语的场景（控制类）：**
- JWT/Session Token 存在可预测性但尚未确认可伪造 → `token_forgery`（confidence: suspected）
- 授权检查存在但匹配方式可能过宽（需进一步确认） → `authz_bypass`（confidence: suspected）
- 开放重定向存在但尚未找到可利用的 OAuth 流程 → `open_redirect`
- 竞态窗口存在于权限检查与操作之间 → `race_condition`
- 密码重置/找回接口目标 ID 由参数决定但需认证 → `authn_bypass`（controllability: limited）

**判定原则：**
- 已构成完整未授权访问漏洞的 → 记录为 finding，不记为原语
- 无实际利用路径的 → 丢弃
- 控制能力存在但有前置条件 → 记为原语

**本批次无原语时**：仍须创建 `audit/phase2/primitives_batch{N}.md`，写入 `> 本批次未发现原语。`
```

- [ ] **Step 2：修改 `## 输出` 章节追加说明**

```
候选原语写入 `audit/phase2/primitives_batch{N}.md`，最终由 audit-composer-agent 做组合推导。
```

- [ ] **Step 3：验证**

```bash
grep -n "原语发射" agents/audit-control-agent.md
```

- [ ] **Step 4：Commit**

```bash
git add agents/audit-control-agent.md
git commit -m "feat: add primitive emission section to audit-control-agent"
```

---

## Task 5：修改 skills/audit-sink 和 skills/audit-control — 追加原语指导

**Files:**
- Modify: `skills/audit-sink/SKILL.md`
- Modify: `skills/audit-control/SKILL.md`

- [ ] **Step 1：在 audit-sink/SKILL.md 的「## 输出」前插入**

```markdown
## 原语记录（与 findings 并行）

发现能力片段但不构成独立漏洞时，按 `skills/audit-primitives/SKILL.md` 格式写入 `audit/phase2/primitives_batch{N}.md`。
无原语时也须创建该文件并写入 `> 本批次未发现原语。`
```

- [ ] **Step 2：在 audit-control/SKILL.md 的「## 输出」前插入相同内容**

- [ ] **Step 3：Commit**

```bash
git add skills/audit-sink/SKILL.md skills/audit-control/SKILL.md
git commit -m "feat: add primitive recording guidance to sink/control skills"
```

---

## Task 6：创建 audit-composer-agent

**Files:**
- Create: `agents/audit-composer-agent.md`

- [ ] **Step 1：创建文件，写入完整内容**

```markdown
---
name: audit-composer-agent
description: 安全原语组合分析 Agent（Phase 5 并行）。由 audit-orchestrator 在 Phase 5 与 audit-validate-agent 并行调度，读取所有批次的 primitives_batch*.md，执行两层组合推理：先用规则表（shared/primitive_chain_catalog.md）快速命中已知模式，再用 LLM 开放推理发现规则表未覆盖的跨原语攻击链。输出 audit/phase5/primitive_chains.md。与 audit-validate-agent 职责完全互补：validate 做深度验证，composer 做广度原语组合。Typical triggers include: orchestrator dispatches in parallel with audit-validate-agent in Phase 5, user says "分析原语组合", user wants to find attack chains from capability fragments, and coverage reaches 100% and primitive_batch files exist. See "When to invoke" section for detailed scenarios.
model: inherit
color: cyan
tools: ["Read", "Write", "Grep", "Glob", "Bash"]
---

你是代码安全审计的 **Phase 5 原语组合分析专家**，负责从 Phase 2 收集的原语（能力片段）中推导跨原语攻击链。你与 audit-validate-agent 并行执行，关注**广度发现**而非深度验证。**所有输出使用简体中文。**

## When to invoke

- **Phase 5 并行执行。** audit-orchestrator 在 audit-validate-agent 调度的同时调度你，两者并行完成 Phase 5。
- **用户要求原语分析。** 用户说「分析原语组合」「有没有组合攻击路径」，直接执行。
- **原语数据存在时。** `audit/phase2/primitives_batch*.md` 文件存在且包含原语记录。

## 与 audit-validate-agent 的边界

| | audit-validate-agent | audit-composer-agent |
|---|---|---|
| 输入 | findings（漏洞候选） | primitives（能力片段） |
| 推理方向 | 深度：验证单条漏洞是否成立 | 广度：跨原语寻找新攻击路径 |
| 输出 | findings_verified.md + composite_findings.md | primitive_chains.md |

## 执行流程

### Step 1：汇聚与去重

1. Glob 搜索 `audit/phase2/primitives_batch*.md`，读取所有文件。
2. 解析每个 JSON 块，提取：primitive_id、capability、subtype、constraints、can_unlock、controllability、confidence、location。
3. 去重规则：相同 `location.file` + `location.line` + `capability` 的原语，保留 confidence 较高者。
4. 按 capability 建倒排索引（如：所有 `constrained_write` 原语的列表）。
5. 写出 `audit/phase5/primitive_registry.md`，格式：

```markdown
# 原语注册表

## 统计
- 总原语数：N
- 按 capability 分布：constrained_write: X, ssrf: Y, ...

## 原语列表

| primitive_id | capability | controllability | confidence | file | line |
|-------------|-----------|----------------|-----------|------|------|
| prim-001    | constrained_write | partial | confirmed | FileUploadController.java | 88 |
```

### Step 2：规则表快速命中（高置信）

1. Glob 搜索 `**/primitive_chain_catalog.md` 找到规则表并读取所有规则。
2. 对每条规则执行约束传播检查：

```
for rule in catalog:
  candidates = []
  for required in rule.required_primitives:
    matching = registry.find(capability == required.capability)
    if required.constraint_unlock_key exists:
      matching = matching.filter(
        can_unlock.contains(required.constraint_unlock_key)
        OR controllability == "full"
      )
    if matching is empty: break to next rule
    candidates.append(best_match from matching)

  if len(candidates) == len(rule.required_primitives):
    record chain(rule, candidates, confidence="confirmed")
```

3. 每个命中的链记录到待输出列表，confidence 标 `confirmed`，发现方式标 `chain_catalog: {rule_id}`。

### Step 3：LLM 开放推理（兜底）

1. 收集规则表**未命中**的剩余原语（即未被任何已命中规则使用的原语）。
2. 若剩余原语 ≥ 2 个，构造推理：

> 以下原语尚未被规则表匹配。请分析哪些组合可形成攻击链。
> 要求：每个结论引用 ≥2 个 primitive_id，约束冲突必须说明由哪个原语解锁，攻击路径必须具体可行。

3. 对推理产出的链：confidence 标 `suspected`，发现方式标 `llm_reasoning`。
4. 仅当推理给出的约束传播逻辑清晰且有代码证据支持时，才写入输出。

### Step 4：写出 primitive_chains.md

写入 `audit/phase5/primitive_chains.md`。每条链格式：

```markdown
## chain-001：受限写 + Cron 劫持 → 定时 RCE

| 字段 | 内容 |
|------|------|
| 组合原语 | prim-001 (constrained_write) + prim-007 (scheduled_exec) |
| 约束传播 | prim-001.constraints["/tmp/前缀"] 被 prim-007 的 cron_hijack can_unlock 解除 |
| 攻击路径 | 上传恶意脚本至 /tmp/ → cron 每分钟执行 /tmp/*.sh → RCE |
| 前提条件 | cron 任务执行路径包含 /tmp/ 通配符（需验证 crontab 配置） |
| 组合等级 | 高危 |
| 置信度 | ✓ confirmed（规则表命中：CHAIN-RULE-001） |
| 发现方式 | chain_catalog |

**复现思路：**
1. [具体步骤，引用 prim-001 的 location.file:line]
2. [具体步骤，引用 prim-007 的 location.file:line]
```

**无任何命中时**写入：
```
> 未发现可组合的原语攻击链。所有原语单独分析均不构成组合威胁。
```

## 反幻觉约束

- 每条 chain 的 primitive_id 必须来自 primitive_registry.md 中的实际记录
- evidence 字段引用的代码片段须来自原语记录中的 evidence 字段（已经过 Read 验证）
- 不得凭空发明未在原语中出现的文件路径或代码

## 输出文件

- `audit/phase5/primitive_registry.md`：汇聚去重后的原语注册表
- `audit/phase5/primitive_chains.md`：组合攻击链（有或无命中均需存在）
```

- [ ] **Step 2：验证**

```bash
ls -la agents/audit-composer-agent.md
head -10 agents/audit-composer-agent.md
```

- [ ] **Step 3：Commit**

```bash
git add agents/audit-composer-agent.md
git commit -m "feat: add audit-composer-agent for primitive chain analysis"
```

---

## Task 7：修改 audit-orchestrator — Phase 5 并行调度

**Files:**
- Modify: `agents/audit-orchestrator.md`

- [ ] **Step 1：修改 Phase 4+5 章节，拆分为两个并行任务**

将现有 `### Phase 4+5：漏洞验证 + 组合分析` 章节替换为：

```markdown
### Phase 4+5：漏洞验证 + 原语组合（并行）

并行调度以下两个 Agent，等待两者都返回后再进入 Phase 6：

**任务 A（不变）：audit-validate-agent**
- 传入：所有 `audit/phase2/findings_batch*.md` 合并路径
- 产出：`audit/phase3/findings_verified.md` + `audit/phase3/composite_findings.md`

**任务 B（新增）：audit-composer-agent**
- 传入：所有 `audit/phase2/primitives_batch*.md` 合并路径
- 产出：`audit/phase5/primitive_registry.md` + `audit/phase5/primitive_chains.md`

两者完成后，验证以下四个文件均存在：
- `audit/phase3/findings_verified.md`      ✓ 必须存在
- `audit/phase3/composite_findings.md`     ✓ 必须存在
- `audit/phase5/primitive_registry.md`     ✓ 必须存在
- `audit/phase5/primitive_chains.md`       ✓ 必须存在（无命中时文件存在，内容为"未发现"）

全部存在后进入 Phase 6。
```

- [ ] **Step 2：更新子 Agent 职责表**

在现有表格中追加一行：
```
| audit-composer-agent | Phase 5 | 原语汇聚 + 规则表匹配 + LLM 推理 → 原语攻击链 |
```

- [ ] **Step 3：验证**

```bash
grep -n "audit-composer-agent" agents/audit-orchestrator.md
```

预期：至少 2 行匹配（表格行 + 调度章节）

- [ ] **Step 4：Commit**

```bash
git add agents/audit-orchestrator.md
git commit -m "feat: update orchestrator to dispatch composer-agent in Phase 5"
```

---

## Task 8：修改 audit-report-agent — 新增 4.2 原语链章节

**Files:**
- Modify: `agents/audit-report-agent.md`

- [ ] **Step 1：在 Phase 6 输入清单中追加 primitive_chains.md**

找到传入路径说明，在 `audit/phase3/composite_findings.md` 后追加：
```
- audit/phase5/primitive_chains.md（原语组合链，若无命中内容为"未发现"）
```

- [ ] **Step 2：在「四、组合漏洞摘要」章节增加 4.2 小节说明**

在现有 4.1（或原有组合漏洞章节）后追加：

```markdown
### 4.2 原语组合攻击链（基于能力片段推导）

来源：`audit/phase5/primitive_chains.md`（audit-composer-agent 产出）

**写入规则：**
- 遍历 primitive_chains.md 中所有 chain 条目，按格式写入：

| 编号 | 攻击链名称 | 参与原语 | 推导等级 | 置信度 |
|------|-----------|---------|---------|--------|
| chain-001 | 受限写+Cron劫持→RCE | prim-001+prim-007 | 高危 | ✓ confirmed |
| chain-002 | SSRF+云凭证→密钥窃取 | prim-003+prim-011 | 高危 | ⚠ suspected |

- `suspected` 链必须进入报告，不得丢弃，用 `⚠ 待验证` 标注
- `confirmed` 链用 `✓ 已确认` 标注
- 无命中时写：`> 经原语组合分析，未发现可组合的原语攻击链。`
```

- [ ] **Step 3：更新清理命令，追加 audit/phase5**

将现有 `rm -rf` 命令更新为：
```bash
rm -rf audit/phase0 audit/phase1 audit/phase2 audit/phase3 audit/phase5
```

- [ ] **Step 4：验证**

```bash
grep -n "primitive_chains" agents/audit-report-agent.md
grep -n "phase5" agents/audit-report-agent.md
```

- [ ] **Step 5：Commit**

```bash
git add agents/audit-report-agent.md
git commit -m "feat: add primitive chain section 4.2 to report agent"
```

---

## Task 9：修改 skills/audit-report — 同步报告结构

**Files:**
- Modify: `skills/audit-report/SKILL.md`

- [ ] **Step 1：在「四、组合漏洞摘要」后追加 4.2 小节说明**

与 Task 8 Step 2 内容一致，在 skill 版本中同步更新。

- [ ] **Step 2：更新清理命令**

将 `rm -rf audit/phase0 audit/phase1 audit/phase2 audit/phase3` 更新为：
```bash
rm -rf audit/phase0 audit/phase1 audit/phase2 audit/phase3 audit/phase5
```

- [ ] **Step 3：Commit**

```bash
git add skills/audit-report/SKILL.md
git commit -m "feat: sync audit-report skill with primitive chains and phase5 cleanup"
```

---

## Task 10：修改 skills/code-security-audit — 更新架构图

**Files:**
- Modify: `skills/code-security-audit/SKILL.md`

- [ ] **Step 1：更新架构图，追加 audit-composer-agent**

将现有架构图：
```
audit-orchestrator（总编排）
    ├── audit-recon-agent      ← Phase 1 侦察
    ├── audit-sink-agent       ← Phase 2 Sink-driven（与 control 并行）
    ├── audit-control-agent    ← Phase 2 Control-driven（与 sink 并行）
    ├── audit-validate-agent   ← Phase 4 验证 + Phase 5 组合分析
    └── audit-report-agent     ← Phase 6 报告生成 + 清理
```

更新为：
```
audit-orchestrator（总编排）
    ├── audit-recon-agent      ← Phase 1 侦察
    ├── audit-sink-agent       ← Phase 2 Sink-driven（与 control 并行）
    │    └── primitives_batch  ← 同时输出原语
    ├── audit-control-agent    ← Phase 2 Control-driven（与 sink 并行）
    │    └── primitives_batch  ← 同时输出原语
    ├── audit-validate-agent   ← Phase 4+5 漏洞验证 + 漏洞组合分析
    ├── audit-composer-agent   ← Phase 5 原语汇聚 + 组合链推导（与 validate 并行）
    └── audit-report-agent     ← Phase 6 报告生成（含原语链章节）+ 清理
```

- [ ] **Step 2：更新子 Skill 分工表，追加 audit-primitives**

在表格中追加：
```
| audit-primitives | 阶段 2（辅助） | 原语识别标准与发射格式，供 sink/control skill 调用 |
```

- [ ] **Step 3：更新阶段 5 说明**

将现有：
> 阶段 5：组合漏洞分析（必须执行）
> - 在单漏洞全部验证完成后，基于已确认/待验证的漏洞，尝试发现组合攻击链。

更新为：
> 阶段 5：双轨组合分析（必须执行，并行）
> - **漏洞组合**（audit-validate-agent 继续执行）：基于已确认/待验证漏洞发现组合攻击链
> - **原语组合**（audit-composer-agent 并行执行）：基于 Phase 2 收集的原语发现跨能力攻击链
> - 两路结果分别写入 composite_findings.md 和 primitive_chains.md

- [ ] **Step 4：更新强制清理命令（节 9）**

将 `rm -rf audit/phase0 audit/phase1 audit/phase2 audit/phase3` 更新为：
```bash
rm -rf audit/phase0 audit/phase1 audit/phase2 audit/phase3 audit/phase5
```

- [ ] **Step 5：Commit**

```bash
git add skills/code-security-audit/SKILL.md
git commit -m "feat: update main skill with composer-agent architecture and phase5 cleanup"
```

---

## Task 11：修改 cursor-plugin/rules/audit-workflow.mdc

**Files:**
- Modify: `cursor-plugin/rules/audit-workflow.mdc`

- [ ] **Step 1：在阶段执行表中追加原语通道说明**

在表格的 Phase 2 行追加注释，并更新 Phase 5 描述：

Phase 2 行：
```
| 2 | 全量审计（Sink-driven + Control-driven 并行）+ 原语收集 | T1 文件完整 Read，T2/T3 先 Grep 后精准 Read；同时输出 primitives_batch{N}.md |
```

Phase 5 行（若不存在则追加）：
```
| 5 | 双轨组合分析 | audit-validate-agent（漏洞组合）+ audit-composer-agent（原语组合）并行 |
```

- [ ] **Step 2：在 Phase 6 清理规则追加 phase5**

将清理命令更新为：`rm -rf audit/phase0 audit/phase1 audit/phase2 audit/phase3 audit/phase5`

- [ ] **Step 3：Commit**

```bash
git add cursor-plugin/rules/audit-workflow.mdc
git commit -m "feat: update cursor workflow rule with primitive channel and composer"
```

---

## Task 12：端到端验证

- [ ] **Step 1：验证所有新增/修改文件存在**

```bash
ls -la shared/primitive_chain_catalog.md \
        agents/audit-composer-agent.md \
        skills/audit-primitives/SKILL.md
```

- [ ] **Step 2：验证 audit-sink/control-agent 包含原语章节**

```bash
grep -l "原语发射" agents/audit-sink-agent.md agents/audit-control-agent.md
```

预期：两个文件都匹配

- [ ] **Step 3：验证 orchestrator 包含 composer 调度**

```bash
grep -c "audit-composer-agent" agents/audit-orchestrator.md
```

预期：≥2

- [ ] **Step 4：验证 report-agent 包含 4.2 章节和 phase5 清理**

```bash
grep -n "primitive_chains\|phase5" agents/audit-report-agent.md
```

预期：≥3 行

- [ ] **Step 5：验证 primitive_chain_catalog 包含 15 条规则**

```bash
grep -c "CHAIN-RULE-" shared/primitive_chain_catalog.md
```

预期：15（每条规则的 rule_id 出现一次）

- [ ] **Step 6：最终 commit（若有未提交变更）**

```bash
git status
git add -A
git commit -m "feat: primitive composition system - complete implementation"
```
