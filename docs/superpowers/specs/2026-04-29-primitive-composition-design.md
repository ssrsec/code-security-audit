# 安全原语组合系统设计文档

**日期**：2026-04-29
**项目**：code-security-audit Claude Code Plugin
**状态**：待实现

---

## 1. 背景与目标

### 问题

现有审计框架的组合漏洞分析（Phase 5）只能组合"已经成立的漏洞"（vul-XXX），无法识别单独不构成漏洞的能力片段（如"受限文件写"、"可控定时任务路径"）在组合后产生的高危攻击路径。这导致：

- 广度覆盖不足：多个中低危能力片段叠加成严重漏洞的场景被漏报
- 发现时机滞后：只有漏洞通过 Phase 4 验证后才能做组合，错过了"原语互相解锁约束"的早期发现机会

### 目标

在保证现有漏洞验证路径（audit-validate-agent）完全不变的前提下，叠加一条**原语通道**：

1. Phase 2 审计时，sink/control-agent 同时输出"能力片段"（原语）
2. Phase 5 新增 audit-composer-agent，从原语中推导跨能力的新攻击链
3. Phase 6 报告新增「原语组合攻击链」小节

---

## 2. 整体架构

### 数据流

```
Phase 2（双轨并行）
  ┌─ audit-sink-agent ──────────────────────────┐
  │  输出 A: findings_batch{N}.md    ← 漏洞通道（不变）
  │  输出 B: primitives_batch{N}.md  ← 原语通道（新增）
  └──────────────────────────────────────────────┘
  ┌─ audit-control-agent ───────────────────────┐
  │  输出 A: findings_batch{N}.md    ← 漏洞通道（不变）
  │  输出 B: primitives_batch{N}.md  ← 原语通道（新增）
  └──────────────────────────────────────────────┘

Phase 3 覆盖率校验（不变）

Phase 5（两路并行）
  ┌─ audit-validate-agent ────────────────────────────────────────┐
  │  输入:  findings_batch*.md                                     │
  │  输出:  findings_verified.md + composite_findings.md  ← 不变  │
  └───────────────────────────────────────────────────────────────┘
  ┌─ audit-composer-agent（新增）─────────────────────────────────┐
  │  输入:  primitives_batch*.md（全批次）                         │
  │  步骤1: 合并去重 → primitive_registry.md                       │
  │  步骤2: 规则表匹配 → shared/primitive_chain_catalog.md         │
  │  步骤3: LLM 开放推理（规则表未覆盖的剩余原语）                 │
  │  输出:  audit/phase5/primitive_chains.md                      │
  └───────────────────────────────────────────────────────────────┘

Phase 6 report-agent
  输入新增: audit/phase5/primitive_chains.md
  报告「四、组合漏洞摘要」拆分为 4.1（漏洞组合）+ 4.2（原语组合）
```

### 编号命名空间（互不冲突）

| 类型 | 编号格式 | 产出 Agent |
|------|---------|-----------|
| 单条漏洞 | `vul-001` | audit-validate-agent |
| 漏洞组合链 | `com-001` | audit-validate-agent |
| 原语 | `prim-001` | sink/control-agent |
| 原语组合链 | `chain-001` | audit-composer-agent |

---

## 3. 原语消息格式（audit-primitive/v1）

每条原语写入 `audit/phase2/primitives_batch{N}.md`，格式为 Markdown 文件内嵌 JSON 代码块：

````markdown
### prim-001

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

### 3.1 字段规范

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `schema` | string | ✓ | 固定值 `"audit-primitive/v1"` |
| `primitive_id` | string | ✓ | 格式 `prim-NNN`，全局唯一，跨批次不重置 |
| `discovered_by` | string | ✓ | `"audit-sink-agent"` 或 `"audit-control-agent"` |
| `batch` | integer | ✓ | 所属批次号，与文件名对应 |
| `capability` | enum | ✓ | 见 3.2 capability 枚举表 |
| `subtype` | string | ✓ | 细分描述，自由填写 |
| `controllability` | enum | ✓ | `full / partial / limited` |
| `constraints` | string[] | ✓ | 限制该原语能力的条件列表；无约束时填 `[]` |
| `can_unlock` | string[] | ✓ | 该原语能解锁的组合键；与 chain catalog 对应 |
| `location.file` | string | ✓ | 相对项目根的文件路径（必须 Read 验证存在） |
| `location.line` | integer | ✓ | 行号；无法确认时填 `0` 并将 confidence 降为 suspected |
| `location.call_chain` | string | ✓ | 每跳 `文件:行号`，格式同 callchain_tracker |
| `evidence` | string | ✓ | 直接来自 Read 输出的代码片段，不得编造 |
| `standalone_severity` | enum | ✓ | `none / low / medium`（原语不产出 high/critical）|
| `confidence` | enum | ✓ | `confirmed / suspected` |
| `tags` | string[] | — | 自由标签，辅助检索 |

### 3.2 capability 枚举

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

### 3.3 约束传播规则

组合引擎使用两条规则判断原语是否可组合：

1. **直接解锁**：若原语 B 的 `can_unlock` 包含原语 A 的某项约束的解锁键 → B 突破 A 的约束 → 二跳链成立
2. **传递链**：A 突破 B 的约束，B 的能力触达 C 的执行条件 → 三跳链成立

---

## 4. audit-composer-agent 设计

### 4.1 元数据

```yaml
name: audit-composer-agent
color: cyan
model: inherit
tools: ["Read", "Write", "Grep", "Glob", "Bash"]
```

### 4.2 执行流程

**Step 1：汇聚与去重**

```
Glob("audit/phase2/primitives_batch*.md")
→ 解析所有 JSON 块，提取 primitive_id、capability、constraints、can_unlock、location
→ 按 primitive_id 去重（相同 file:line 的同 capability 保留 confidence 更高者）
→ 按 capability 建倒排索引
→ 写出 audit/phase5/primitive_registry.md
```

**Step 2：规则表快速命中（高置信）**

```
读取 shared/primitive_chain_catalog.md
for rule in catalog:
  candidates = []
  for required in rule.required_primitives:
    matching = registry.find(capability == required.capability)
    if required.constraint_unlock_key:
      matching = matching.filter(
        can_unlock.contains(required.constraint_unlock_key)
        OR controllability == "full"
      )
    if matching.empty: break
    candidates.append(matching)
  if len(candidates) == len(rule.required_primitives):
    emit chain(rule, candidates, confidence="confirmed")
```

**Step 3：LLM 开放推理（兜底，低置信）**

将规则表未命中的剩余原语送入推理：
- 输入：primitive_id + capability + constraints + can_unlock 的精简列表
- 要求：每个结论必须引用 ≥2 个 primitive_id 作为证据，约束冲突必须说明由哪个原语解锁
- 产出：`confidence: "suspected"` 的链候选

### 4.3 输出格式（primitive_chains.md）

每条链一个 Markdown 章节：

```markdown
## chain-001：受限写 + Cron 劫持 → 定时 RCE

| 字段 | 内容 |
|------|------|
| 组合原语 | prim-001 (constrained_write) + prim-007 (scheduled_exec) |
| 约束传播 | prim-001.constraints["/tmp/前缀"] 被 prim-007 的 cron_hijack 解锁 |
| 攻击路径 | 上传恶意脚本至 /tmp/ → cron 每分钟执行 /tmp/*.sh → RCE |
| 前提条件 | cron 任务执行路径包含 /tmp/ 通配符（需验证 crontab 配置） |
| 组合等级 | 高危 |
| 置信度 | ✓ confirmed（规则表命中：CHAIN-RULE-001） |
| 发现方式 | chain_catalog |

**复现思路：**
1. POST /api/upload 上传 shell.sh 至 /tmp/shell.sh（利用 prim-001）
2. 等待 cron 触发 /tmp/*.sh（依赖 prim-007 的定时器配置）
3. 执行反弹 shell
```

无命中时写：`> 未发现可组合的原语攻击链。`

---

## 5. primitive_chain_catalog.md 规则表

位置：`shared/primitive_chain_catalog.md`

### 5.1 规则结构

```json
{
  "rule_id": "CHAIN-RULE-001",
  "name": "受限写 + 定时任务 → 定时代码执行",
  "required_primitives": [
    {
      "capability": "constrained_write",
      "constraint_unlock_key": "cron_hijack"
    },
    {
      "capability": "scheduled_exec"
    }
  ],
  "constraint_propagation": "constrained_write 的路径约束须包含 cron 执行目录或通配符路径",
  "resulting_capability": "arbitrary_code_execution",
  "resulting_severity": "高危",
  "attack_narrative": "写入恶意脚本至 cron 可执行路径 → 等待定时触发 → RCE",
  "confidence": "confirmed"
}
```

### 5.2 预置规则集（15 条）

| rule_id | 原语 A | 原语 B | 原语 C | 组合结果 | 等级 |
|---------|--------|--------|--------|----------|------|
| CHAIN-RULE-001 | constrained_write | scheduled_exec | — | 定时 RCE | 高危 |
| CHAIN-RULE-002 | constrained_write | path_traversal（can_unlock） | — | 任意写 → Webshell | 严重 |
| CHAIN-RULE-003 | constrained_read | path_disclosure（can_unlock） | — | 任意文件读 | 高危 |
| CHAIN-RULE-004 | ssrf | deserialization_exec | — | 内网 RCE | 严重 |
| CHAIN-RULE-005 | ssrf | credential_leak | — | 云凭证窃取（metadata）| 高危 |
| CHAIN-RULE-006 | sql_injection | arbitrary_write | — | INTO OUTFILE → Webshell | 严重 |
| CHAIN-RULE-007 | token_forgery | authz_bypass | — | 完全权限提升 | 严重 |
| CHAIN-RULE-008 | credential_leak | authn_bypass | — | 账户接管 | 高危 |
| CHAIN-RULE-009 | constrained_write | source_disclosure | — | 配置覆盖 → 行为劫持 | 高危 |
| CHAIN-RULE-010 | template_injection | logic_bypass | — | 沙箱逃逸 → RCE | 严重 |
| CHAIN-RULE-011 | race_condition | authz_bypass | — | TOCTOU 权限提升 | 高危 |
| CHAIN-RULE-012 | prototype_pollution | expression_injection | — | 原型链污染 → RCE | 严重 |
| CHAIN-RULE-013 | open_redirect | token_forgery | — | OAuth 回调劫持 → 账户接管 | 高危 |
| CHAIN-RULE-014 | constrained_read | credential_leak | — | 配置文件读取 → 密钥泄露 | 高危 |
| CHAIN-RULE-015 | ssrf | sql_injection | arbitrary_write | 三跳：内网注入 + 写 Shell | 严重 |

### 5.3 扩展约定

- 新增规则追加 JSON 块，`rule_id` 按 `CHAIN-RULE-NNN` 递增
- `resulting_severity` 只允许 `严重 / 高危 / 中危`，原语组合不产出低危
- 三跳规则在 `required_primitives` 中列三项，引擎逻辑不变

---

## 6. Orchestrator 调度变更

仅两处最小改动：

### 6.1 Phase 2：Phase 2 Agent 增加原语输出

在现有 Phase 2 调度注释中追加说明：
```
audit-sink-agent 和 audit-control-agent 在完成 findings_batch{N}.md 后，
同时输出 primitives_batch{N}.md（可为空文件）
```

### 6.2 Phase 5：新增并行 composer 调度

```
Phase 5 调度（并行）：
  任务 A：audit-validate-agent ← 传入 findings_batch*.md 路径（不变）
  任务 B：audit-composer-agent ← 传入 primitives_batch*.md 路径（新增）

等待两者完成，验证以下四个文件均存在：
  audit/phase3/findings_verified.md      ✓
  audit/phase3/composite_findings.md     ✓
  audit/phase5/primitive_registry.md     ✓
  audit/phase5/primitive_chains.md       ✓（无命中时文件存在但内容为"未发现"）
```

---

## 7. Phase 6 报告整合

### 7.1 章节结构变更

「四、组合漏洞摘要」拆分为两个小节，**五章节结构不变**：

```markdown
## 四、组合漏洞摘要

### 4.1 漏洞组合攻击链（基于已确认漏洞）

来源：composite_findings.md

| 编号 | 组合漏洞 | 参与漏洞 | 组合后等级 |
|------|---------|---------|-----------|
| com-001 | SSRF + 内网反序列化 | vul-003 + vul-007 | 严重 |

### 4.2 原语组合攻击链（基于能力片段推导）

来源：primitive_chains.md

| 编号 | 攻击链 | 参与原语 | 推导等级 | 置信度 |
|------|--------|---------|---------|--------|
| chain-001 | 受限写+Cron劫持→RCE | prim-001+prim-007 | 高危 | ✓ confirmed |
| chain-002 | SSRF+云凭证→密钥窃取 | prim-003+prim-011 | 高危 | ⚠ suspected |
```

### 7.2 suspected 链处理规则

- 必须进入报告，不得丢弃
- 「前提条件」字段逐条列出需人工验证的具体项
- 用 `⚠ 待验证` 标注，与 `✓ 已确认` 视觉区分

### 7.3 清理规则追加

Phase 6 收尾 `rm -rf` 追加 `audit/phase5`：

```bash
rm -rf audit/phase0 audit/phase1 audit/phase2 audit/phase3 audit/phase5
# 保留 audit/decompiled（反编译源码基础）
```

---

## 8. 新增文件清单

| 文件路径 | 类型 | 说明 |
|---------|------|------|
| `shared/primitive_chain_catalog.md` | 新建 | 15 条预置规则表 |
| `agents/audit-composer-agent.md` | 新建 | 原语组合 Agent |
| `skills/audit-primitives/SKILL.md` | 新建 | 原语识别指导 skill |
| `agents/audit-sink-agent.md` | 修改 | 追加原语输出章节 |
| `agents/audit-control-agent.md` | 修改 | 追加原语输出章节 |
| `agents/audit-orchestrator.md` | 修改 | Phase 5 并行调度变更 |
| `agents/audit-report-agent.md` | 修改 | 新增 4.2 小节逻辑 |
| `skills/code-security-audit/SKILL.md` | 修改 | 架构图更新 |
| `cursor-plugin/rules/audit-workflow.mdc` | 修改 | 原语通道说明 |

---

## 9. 实现约束

- `audit-validate-agent` **零改动**，保证现有漏洞验证路径稳定
- 原语发现是**尽力而为**：Phase 2 agent 若在某批次未发现任何原语，输出空的 `primitives_batch{N}.md` 即可，不阻塞流程
- `audit-composer-agent` 必须在规则表和 LLM 推理之后才写 `primitive_chains.md`，不允许提前写入空文件
- 所有原语的 `evidence` 字段必须来自 Read 工具的实际输出，不得编造（反幻觉铁律同样适用）
- `primitive_id` 跨批次连续递增（prim-001 在 batch1，prim-008 在 batch2），不按批次重置
