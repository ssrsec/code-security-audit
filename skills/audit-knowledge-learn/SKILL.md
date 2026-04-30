---
name: audit-knowledge-learn
description: 审计知识自学习技能。在 Phase 6 报告生成后由 orchestrator 调度，从已验证漏洞中提取可复用的漏洞模式，自动沉淀为新的知识库文件或更新现有文件。借鉴 TCH 赛事绿盟/奇盾战队的经验沉淀机制。当审计完成后触发知识沉淀，或用户说「沉淀审计经验」「更新知识库」时触发。
---

# 审计知识自学习（Phase 6 后置）

## 角色

在审计完成后，从已验证漏洞中提取可复用的检测模式和验证条件，沉淀到知识库中。这是一个**增量学习**过程：每次审计都可能发现知识库中未覆盖的漏洞模式或需要更新的条件。

## 输入

- `audit/phase4/validated_findings.md` — 已验证的漏洞
- `audit/phase5/composite_findings.md` — 组合漏洞
- `audit/phase5/primitive_chains.md` — 原语链
- `audit/security_audit_report.md` — 最终报告
- `skills/audit-validate/resources/knowledge/` — 现有知识库

## 触发条件

- Phase 6 报告生成完成后，orchestrator 自动调度。
- 用户说「沉淀审计经验」「更新知识库」时手动触发。
- 仅当 validated_findings.md 中存在 V2+ 级别的已确认漏洞时执行。

## 提取规则

### 1. 候选模式筛选

从 validated_findings.md 中筛选满足以下条件的漏洞：

- **验证等级 ≥ V2**：已通过代码或测试验证的确认漏洞。
- **有完整调用链**：source-to-sink 或控制缺失链完整。
- **非项目特定**：漏洞模式可泛化到其他同技术栈项目。

排除：
- V0/V1 待验证漏洞（证据不足）。
- 仅依赖特定业务逻辑的漏洞（如特定支付流程）。
- 已在知识库中完整覆盖的已知模式。

### 2. 模式提取

对每个候选漏洞，提取：

```markdown
## 模式名称

### 发现条件（如何搜索）
- Sink 模式/API 签名
- 框架/版本特征
- 配置特征

### 成立条件（什么时候是漏洞）
- 外部输入可控条件
- 防护缺失条件
- 版本/配置条件

### 不成立条件（什么时候是误报）
- 有效防护模式
- 版本修复条件
- 框架自带安全特性

### 验证方法
- 静态验证步骤
- 动态验证方法（如适用）

### 来源审计
- 项目技术栈
- 发现日期
- 原始 finding ID
```

### 3. 知识库更新策略

| 场景 | 操作 |
|------|------|
| 新漏洞类型（现有知识库无对应文件） | 创建新 `xxx_conditions.md` |
| 现有类型的新变体（如新框架的 SQL 注入模式） | 在现有文件中追加章节 |
| 现有条件需修正（如版本范围不准确） | 更新现有文件的对应条件 |
| 新原语链模式 | 追加到 `shared/primitive_chain_catalog.md` |
| 新框架鉴权检查清单 | 追加到 `shared/framework_authz_checklist.md` |

### 4. 去重与合并

- 提取模式前，先 Grep 搜索知识库中是否已存在相同或相似模式。
- 相同模式 → 跳过。
- 相似但有差异 → 合并（保留两者信息）。
- 全新模式 → 创建。

## 输出

### 新知识文件

位置：`skills/audit-validate/resources/knowledge/learned/`

文件名规范：`{vuln_type}_{framework}_{date}.md`

示例：`springel_injection_spring_2026-04-30.md`

### 知识学习报告

位置：`audit/knowledge_learn_report.md`

```markdown
# 知识学习报告

## 学习概要
- 审计项目：{project_name}
- 已验证漏洞数：{count}
- 提取候选模式数：{candidate_count}
- 新增知识文件数：{new_files}
- 更新知识文件数：{updated_files}
- 跳过（已覆盖）：{skipped_count}

## 新增模式
1. {模式名称} → `learned/{filename}`
2. ...

## 更新模式
1. {知识库文件} — {更新内容摘要}
2. ...

## 未沉淀（项目特定）
1. {finding_id} — {原因}
2. ...
```

### 知识库版本更新

对所有新增或更新的知识库文件，将 YAML 头部的 `last_updated` 更新为当前日期，`version` 递增。

## 安全约束

- **不沉淀项目敏感信息**：提取的模式中不得包含项目名称、具体 URL、内部路径、凭据等。
- **不沉淀未验证模式**：只有 V2+ 的确认漏洞才能进入知识库。
- **不自动修改核心知识库**：新模式优先放入 `learned/` 子目录，经人工确认后再合并到主知识库。

## 与现有组件的关系

| 组件 | 关系 |
|------|------|
| audit-validate-agent | 消费知识库；本 skill 更新知识库 |
| audit-composer-agent | 消费原语链目录；本 skill 更新目录 |
| audit-advisor-agent | 可在后续审计中检查是否应用了新学到的模式 |
