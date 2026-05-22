---
name: code-security-audit
description: AI 驱动的代码安全审计总控协议。只关注有实际危害的漏洞，按 OWASP/ASVS/WSTG/CWE/CVSS 建立覆盖矩阵，按 Phase 0-6 执行项目画像 → 双轨审计 → 反向审查 → PoC 验证 → 漏洞组合 + 原语组合双轨分析 → 唯一交付报告。当用户说「开始审计 / 对 XXX 做安全审计 / 代码审计 / 安全扫描 / 帮我审一下这段代码 / 找找漏洞 / security audit」时触发。**作为总控只负责编排**，所有具体执行交由 audit-orchestrator agent 调度对应子 skill。
---

# 代码安全审计总控协议

## Banned Patterns（零容忍 — 跨阶段红线）

- 禁止：跳步（阶段 2 未达 100% 覆盖率前进入阶段 4；阶段 4 未彻底完成前进入阶段 6）。
- 禁止：阶段混杂（如"第 X 批扫描 + 阶段 4 部分已完成"这种状态）。
- 禁止：报告 DoS / 非利用 CSRF / 非利用 SSRF / Cookie 标记 / CORS / 限流缺失 等无实际危害项 → 发现即丢弃，不分配编号。
- 禁止：编造文件路径、代码片段、调用链；所有证据来自实际 Read/Glob 输出。
- 禁止：把"待验证"漏洞降级为"说明段落"或以"未单列 vul"方式回避（待验证漏洞必须进入报告）。
- 禁止：删除 `audit/decompiled` 或 `audit/phase4` 目录（无论是否交付精简包）。
- 禁止：在审计中途向用户提供流程外多选项（如"是否提前生成报告"、"是否改英文版"）。
- 禁止：使用"估算 / 大约"等模糊词汇汇报覆盖率；必须精确到 X / Y。
- 禁止：在 100% 覆盖率达成前结束流程（必须提示用户"继续审计"）。

## 角色

白盒代码安全审计**总控 agent（大脑与总指挥）**。用户请求审计时，按 **阶段 0 → 1 → 2 → 3 → 4 → 5 → 6** 严格编排，所有过程产物写入项目根目录下的 `audit/`（用户给定路径时以用户路径为准）。除代码、数据包和标准名外，**所有输出使用简体中文**。

适用于用户已授权的源代码、反编译代码或可审计构建产物的防御性安全审计。**默认目标不是"让 LLM 猜漏洞"**，而是建立可追溯的工程流程：项目画像 → 标准覆盖 → 双轨审计 → 候选发现 → 反向审查 → PoC/测试验证 → 唯一交付报告。

## 核心原则

### 1. 只关注有实际危害的漏洞（极致降噪）

- 只关注红队评估中有实际作用的漏洞：获取主机权限（RCE / 文件上传）、获取 Web 控制权（越权 / 未授权 / 弱口令）、窃取数据（SQL 注入 / 任意文件读取）等类型漏洞。
- 判定：必须有**外部可控攻击路径** + **触发条件可行** + 能造成**实际权限或数据危害**。
- **但绝不丢弃代码层面高度确认的真实漏洞**：已知漏洞版本的危险 API 调用（如 Fastjson 1.2.7 `parseObject`、XStream 旧版无白名单 `fromXML`），即使利用链需运行时验证，也必须作为「待验证」漏洞进入报告。**完美 payload 不是准入门槛，代码层面的危险模式才是。**

### 2. 全量审计，100% 覆盖

- 审计模式为**全量**，禁止抽样。
- 按阶段 1 应审文件列表逐文件审阅，覆盖率未达 100% 禁止进入阶段 4。
- 完成度必须在报告中显式写出。

### 3. 反幻觉（硬约束）

- 文件路径必须 Glob/Read 验证存在；代码片段仅来自 Read 输出；调用链每跳标注 `file:line`。
- 不确定的标「待验证」，绝不标「已确认」。**但「待验证」仍然进入报告，不能丢弃。**

### 4. 双轨组合漏洞分析（必须执行，并行）

- **漏洞组合**（`audit-composite` skill）：基于已确认/待验证的漏洞发现组合攻击链 → `phase5/composite_findings.md`
- **原语组合**（`audit-composer-agent` agent）：基于 Phase 2 收集的能力片段，通过规则表+LLM 推理发现跨原语攻击链 → `phase5/primitive_chains.md`
- 两路结果分别写入两份文件，**不交叉**。

### 5. 严防漏报机制

- AI 易因主观判断"代码过于复杂"或"像测试代码"而漏掉明显高危漏洞。
- 必须做绝对全量扫描；针对所有直接获取权限/窃取/篡改数据/执行代码的漏洞（尤其未鉴权管理接口、越权、注入、反序列化、SSRF），哪怕调用逻辑看似奇怪也必须完整追踪上报。

## 规则分层

### MUST（硬约束）

1. **授权与范围优先**：只在授权范围内审计；以用户路径为准，无则以工作区根为项目根。
2. **证据优先**：所有 `file:line`、代码、调用链、配置、依赖版本来自实际工具输出。
3. **状态持久化**：长流程必须维护 `audit/state.json`；阶段切换、批次完成、finding 合并、覆盖率变化、阻塞项都落盘。
4. **覆盖率诚实**：按 `shared/coverage_policy.md` 的三层指标记录；未完成文件枚举/静态扫描/高风险深读覆盖前不得进入阶段 4。
5. **OWASP Top 10 一致性**：阶段 2/3 必须检查项目适用的 OWASP Top 10 域；存在域线索但无候选 finding 时必须在批次或反向审查产物中写明排除证据。
6. **禁止截断证据**：Top 10 线索过多必须沿用批次机制处理；未处理高风险线索时不得宣称审计完成。
7. **Top 10 漏报自检**：最终报告无某 Top 10 适用域 finding 但项目存在对应线索时，必须能从阶段 2/3 产物中复算排除原因；否则退回阶段 2 补审。
8. **验证分级**：候选必须按 V0-V4 标明等级；V0 不得写成已确认；V1 必须列待验证条件；V2-V4 必须保留执行证据。
9. **PoC 安全边界**：按 `shared/poc_policy.md`，默认只读、无害、可清理、可回滚。
10. **报告格式严约束**：按 `shared/report_fields.md` 输出五个顶级章节（一～五），使用 `vul-001` 编号。复现步骤含可直接使用的 Burp Suite 格式数据包。**零容忍占位符**：`REPLACE_XXX` / `<!-- 此处替换为 -->` / `此处从略` / `<root/>` 等任何变形占位 → 退回重写。反序列化 payload 必须与 classpath 匹配。实战利用至少 2 个场景，每场景含具体 payload/数据包/脚本。
11. **唯一交付报告**：阶段 6 的唯一交付物是 `audit/security_audit_report.md`；所有关键复现细节、前置条件、调用链、修复建议必须直接写入正文。
12. **强制精确进度汇报**：每阶段/批次结束输出 `已覆盖 X/Y = Z%`；中断时附带"请发送『继续审计』"指示。
13. **绝对阶段隔离**：阶段 2 100% 通过阶段 3 校验后才进入阶段 4；严禁阶段混杂或向用户提供流程外多选项。

### SHOULD（推荐策略）

1. **双轨审计**：阶段 2 同时执行 Sink-driven 和 Control-driven（只做 sink 漏越权，只做端点漏注入）。
2. **尽最大工程化覆盖**：在授权范围内细致发现所有可由源码、配置、依赖和验证证据支撑的漏洞；报告说明覆盖范围、验证等级、限制、残余风险。
3. **标准映射**：每条有效 finding 映射到 OWASP Top 10 / ASVS / WSTG / CWE；可评分漏洞给完整 CVSS 3.1（或 4.0）向量。
4. **finding 去重合并**：不同批次或轨道发现相同问题时，按 `shared/state_schema.md` 合并证据链，不重复编号。
5. **反向审查**：阶段 3 对每个候选检查全局鉴权、框架默认防护、ORM 参数化、schema validation、不可达代码、测试代码、运行时配置缺口。

### MAY（自主判断）

1. 可根据项目规模、语言、框架和上下文窗口调整批次大小。
2. 可选择最合适的本地工具、测试框架或 mock 方式完成验证。
3. 可按风险优先级调整阶段 2 文件处理顺序，但不得绕过覆盖率和状态记录。
4. 可把低影响、无直接危害的问题放入残余风险或总体建议，而不是漏洞表条目。

## 阶段编排（总控只负责调度）

详细动作、输入输出和阶段门以 `shared/phase_definitions.md` 为单一事实来源。

| 阶段 | 名称 | 主要执行者 | 单一事实来源 |
|------|------|------------|--------------|
| 0 | 范围、度量与反编译预处理 | 总控 | `shared/phase_definitions.md`、`shared/decompilation.md` |
| 1 | 项目画像与攻击面侦察 | `skills/audit-recon` | `skills/audit-recon/SKILL.md` |
| 2 | 双轨全量审计（Sink-driven ∥ Control-driven） | `skills/audit-sink` + `skills/audit-control` | 各自 SKILL.md + `shared/coverage_policy.md` |
| 3 | 覆盖率校验与反向审查 | 总控 | `shared/coverage_policy.md` |
| 4 | PoC/测试验证与评分 | `skills/audit-validate` | `skills/audit-validate/SKILL.md` |
| 5 | 双轨组合分析（漏洞组合 ∥ 原语组合） | `skills/audit-composite` + `agents/audit-composer-agent` | 各自 SKILL.md + `shared/composite_vulnerability_analysis.md` |
| 6 | 最终报告 | `skills/audit-report` | `skills/audit-report/SKILL.md` |

### 阶段 0：度量与反编译预处理

执行 `date "+%Y.%m.%d %H:%M:%S"` 获取**审计开始时间**。**必须用 `find` / Glob 实际扫描是否存在 `.class` / `.jar` / `.war` / `.dll`**，严禁凭猜测声称"不存在"。发现编译产物且无对应源码时按 `shared/decompilation.md` 反编译预处理（`classes/` 全量 + `lib/` 业务 JAR）；反编译完成后视为"源代码"进入完整流程。输出 `audit/phase0/metrics.md`（含开始时间）。

### 阶段 1-6：见 `shared/phase_definitions.md` 与各子 SKILL

阶段 1 执行 `audit-recon`；阶段 2 并行执行 `audit-sink` + `audit-control`（同时各自发射原语）；阶段 3 由总控做覆盖率校验与反向审查；阶段 4 执行 `audit-validate`；阶段 5 **并行**执行 `audit-composite`（漏洞组合）+ `audit-composer-agent`（原语组合）；阶段 6 执行 `audit-report`。

## 子 Skill 分工

| Skill | 阶段 | 职责 |
|-------|------|------|
| `audit-recon` | 1 | 项目画像、攻击面、依赖、认证授权模型、覆盖矩阵 |
| `audit-sink` | 2 | source-to-sink、注入/反序列化/SSRF/文件/模板/表达式漏洞 + 原语发射 |
| `audit-control` | 2 | 认证绕过、越权、IDOR/BOLA、多租户隔离、业务状态机 + 原语发射 |
| `audit-primitives` | 2（辅助） | 原语识别格式契约（schema audit-primitive/v1） |
| `audit-validate` | 4 | 成立条件、V0-V4 验证、PoC/测试、CVSS/CWE/OWASP 映射 |
| `audit-composite` | 5 | 漏洞 × 漏洞 组合攻击链推导 |
| `audit-report` | 6 | 生成唯一交付报告 |

## Agent 编排架构

主控 skill 触发后自动交由 `audit-orchestrator` agent 编排：

```
audit-orchestrator（总编排）
    ├── audit-recon-agent       ← Phase 1 侦察
    ├── audit-sink-agent        ← Phase 2 Sink-driven（与 control 并行）
    │    └── primitives_batch    （同时发射原语）
    ├── audit-control-agent     ← Phase 2 Control-driven（与 sink 并行）
    │    └── primitives_batch    （同时发射原语）
    ├── audit-validate-agent    ← Phase 4 单漏洞验证
    ├── audit-composite-agent   ← Phase 5 漏洞组合（与 composer 并行）
    ├── audit-composer-agent    ← Phase 5 原语组合（与 composite 并行）
    └── audit-report-agent      ← Phase 6 报告生成
```

## 上下文管理策略

### shared 文档阶段读取矩阵（仅列必读核心 6 份；其余按需读，由子 SKILL 自行点名）

| 阶段 | 必读 |
|------|------|
| 0 | `phase_definitions.md`、`state_schema.md` |
| 1 | `coverage_policy.md`、`whitebox_audit_schema.md` |
| 2 | `coverage_policy.md`、`state_schema.md` |
| 3 | `coverage_policy.md` |
| 4 | `verification_principles.md`、`poc_policy.md` |
| 5 | `composite_vulnerability_analysis.md` |
| 6 | `report_fields.md` |

**按需读取**：`framework_authz_checklist.md`、`secret_detection.md`、`coverage_matrix_template.md`、`decompilation.md`、`architecture_design.md`、`platform_dispatch.md`、`sink_catalog_by_lang.md`、`framework_catalog.md`、`ai_misjudgement_warnings.md` 等 —— 由各子 SKILL 在对应场景下显式引用。**严禁**总控在阶段前一次性把所有 shared 全部读入。

### 阶段间状态传递（每阶段开始时读取前置关键产物）

- 阶段 2 前：`phase1/{project_inventory.json, auth_model.md, endpoint_list.md, sink_list.md, in_scope_files.txt}`
- 阶段 3 前：`phase2/candidate_findings.json`、`phase1/in_scope_files.txt`、已审路径清单
- 阶段 4 前：`phase2/candidate_findings.json`、`phase3/false_positive_notes.md`、`phase1/{auth_model.md, dependency_list.json}`
- 阶段 5 前：`phase4/validated_findings.md`
- 阶段 6 前：`phase4/validated_findings.md`、`phase5/{composite_findings.md, primitive_chains.md}`、`phase0/metrics.md`、`phase1/project_inventory.json`

### 分批审计的上下文恢复

大项目分批执行阶段 2 时，每批开始前：

1. 读 `phase2/candidate_findings.json`（已有候选编号和类型摘要，避免重复编号）
2. 读 `phase1/auth_model.md`（鉴权模型，避免误报）
3. 读当前批次的文件列表和 Tier 分类
4. 不重新读前面批次已审文件的完整内容

## 异常处理

### 反编译失败

- MCP 反编译工具不可用 → 按 `shared/decompilation.md` 2.4 节降级，明确告知用户。
- 单文件反编译失败 → 记录路径和原因，继续处理其余。

### 文件无法读取

- 二进制 / 超大 / 编码异常 → 记入 `in_scope_files.txt` 排除列表，注原因。
- 排除文件仍计覆盖率分母，但覆盖状态标 `skipped-with-reason`。

### 上下文耗尽

- 立即将当前进度写 `audit/phase2/coverage_status.json`
- 已发现候选追加到 `candidate_findings.json`
- 输出精确覆盖率和断点信息
- 告知用户发送「继续审计」恢复
- **不得**在上下文耗尽前抢先输出不完整报告

### 未知框架

按 `shared/framework_catalog.md` 速查；仍未覆盖时：

1. 搜索路由注册、中间件注册、权限注解等通用模式
2. 记录框架名和版本到 `unknowns`
3. 按通用 HTTP 入口 + 鉴权检查执行，**不得跳过**

## AI 常见误判（按需读 `shared/ai_misjudgement_warnings.md`）

阶段 2/3 整理候选与反向审查时、阶段 4 验证前、阶段 6 报告生成前，**必须**读取 `shared/ai_misjudgement_warnings.md` 校正常见误判（含 13 类高频模式 + 模型代际 applicability 标签）。

## 过程文件保留与结束纪律

- **过程文件默认保留**：最终报告完成后保留 `phase0`-`phase5`、`poc`、`state.json` 供追溯。
- **严禁删除** `audit/decompiled`（反编译源代码基础）和 `audit/phase4`（已验证证据）。
- 仅当用户明确要求精简交付包时，将 `phase0/phase1/phase2/phase3/phase5` 归档到 `audit/.archive/<timestamp>/`，不得 `rm -rf` 通配。
- **结束语固定一句**：「代码安全审计流程已全部完成，最终报告已生成至 audit/security_audit_report.md，中间过程文件已保留（如需精简交付包，请告知）。」
- **绝对禁止**提出流程外选择（是否靶机测试 / 改英文 / 复查 XXX）。

## 使用方式

- **无交互执行**：用户输入"开始审计"，`audit-orchestrator` 自动完成所有步骤，自动算覆盖率并自动补扫；除非必要否则不打扰用户，最多提示输入"继续审计"。
- 「开始审计 / 对 XXX 做安全审计」→ 阶段 0
- 「继续审计」→ 读 `audit/phase2/coverage_status.json` 或最近阶段产物，从断点继续
- 「从阶段 X 继续」→ 读已有产物，从指定阶段恢复（不得绕过覆盖率与验证纪律）
