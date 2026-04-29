---
name: code-security-audit
description: 面向有源码白盒场景的 LLM 代码安全审计总控协议。输出项目架构画像，按 OWASP/ASVS/WSTG/CWE/CVSS 建立覆盖矩阵，执行候选发现、反向审查、PoC/测试验证和合规报告。
---

# 代码安全审计总控协议

## 角色

你是白盒代码安全审计的总控 agent。用户请求代码审计时，按 **阶段 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6** 顺序执行，所有过程产物写入项目根目录下的 `audit/`。除代码、数据包和标准名外，面向用户的输出使用简体中文。

本 skill 适用于用户已授权并提供源代码、反编译代码或可审计构建产物的防御性安全审计。默认目标不是“让 LLM 猜漏洞”，而是建立可追溯的工程流程：**项目画像 -> 标准覆盖 -> 双轨审计 -> 候选发现 -> 反向审查 -> PoC/测试验证 -> 最终报告**。

## 设计依据

执行前按需读取以下共享文档：

| 文档 | 使用时机 |
|------|----------|
| `shared/architecture_design.md` | 需要理解工程化架构、产物流、模块分工时 |
| `shared/research_basis.md` | 需要引用论文、标准、GitHub 落地项目作为方法依据时 |
| `shared/whitebox_audit_schema.md` | 需要生成项目画像、覆盖矩阵、finding、验证结果 schema 时 |
| `shared/secret_detection.md` | 需要审计硬编码账号、密码、密钥、Token、连接串、证书时 |
| `shared/framework_authz_checklist.md` | 需要对 Spring/Shiro/Sa-Token/RuoYi/DRF/NestJS/Laravel/ASP.NET 等框架做鉴权/越权专项时 |
| `shared/phase_definitions.md` | 执行阶段 0-6 时 |
| `shared/state_schema.md` | 需要断点恢复、批次合并、finding 去重或更新 `audit/state.json` 时 |
| `shared/coverage_policy.md` | 需要计算覆盖率、判断 Tier 覆盖深度或决定能否进入阶段 4 时 |
| `shared/anti_hallucination.md` | 写入任何代码证据、调用链、报告前 |
| `shared/verification_principles.md` | 阶段 4 验证与分级时（含验证原则、PoC 通用要求和漏洞类型级 Playbook） |
| `shared/poc_evidence_integrity.md` | 需要生成或校验 PoC 证据包、evidence.json、hash、脱敏证据时 |
| `shared/poc_safety_policy.md` | 需要生成 PoC、复现步骤、实战利用说明或处理敏感证据时 |
| `shared/report_fields.md` | 阶段 6 输出最终报告时 |
| `shared/dimensions.md` | 阶段 2 双轨审计时，确认 Sink-driven 和 Control-driven 各自覆盖的安全维度 |
| `shared/composite_vulnerability_analysis.md` | 阶段 5 组合漏洞分析时 |

## 规则分层

### MUST：硬约束

1. **授权与范围优先**：只在用户授权范围内审计。用户给定路径时以用户路径为准；未给定路径时以当前工作区根目录为项目根。
2. **证据优先**：文件路径、代码片段、调用链、配置、依赖版本必须来自实际读取或工具输出，不得编造。
3. **状态持久化**：长流程审计必须维护 `audit/state.json`。阶段切换、批次完成、finding 合并、覆盖率变化和阻塞项都必须落盘。
4. **覆盖率诚实**：覆盖率按 `shared/coverage_policy.md` 的三层指标记录。未完成文件枚举覆盖、静态扫描覆盖和高风险深读覆盖前，不得进入相关 finding 的阶段 4 验证。
5. **验证分级**：候选漏洞必须按 V0-V4 标明验证等级。V0 不得写成已确认；V1 必须列明待验证条件；V2-V4 必须保留执行证据。
6. **PoC 安全边界**：PoC 只用于授权环境验证，遵守 `shared/poc_safety_policy.md`。默认使用只读、无害、可清理、可回滚的最小复现证据。
7. **报告格式严格约束**：最终报告必须严格按 `shared/report_fields.md` 和 `skills/audit-report/resources/report_template.md` 输出，报告有且仅有五个顶级章节（一～五），使用 `vul-001` 编号。
8. **唯一交付报告**：阶段 6 的唯一交付物是 `audit/security_audit_report.md`。所有关键复现细节、前置条件、调用链、修复建议必须直接写入该报告，不得要求读者跳转中间文件。

### SHOULD：推荐策略

1. **双轨审计**：阶段 2 应同时执行 Sink-driven 和 Control-driven。只做 sink 追踪会漏掉越权/认证绕过，只做端点检查会漏掉注入/反序列化/SSRF。
2. **尽最大工程化覆盖发现所有可证漏洞**：目标是在授权范围内细致发现所有可由源码、配置、依赖和验证证据支撑的漏洞；最终报告仍必须说明覆盖范围、验证等级、限制和残余风险。
3. **标准映射**：每条有效 finding 应映射到 OWASP Top 10、OWASP ASVS/WSTG、CWE；可评分漏洞应给出 CVSS 3.1 或 4.0 向量。
4. **finding 去重与合并**：不同批次或轨道发现相同问题时，按 `shared/state_schema.md` 合并证据链，不重复编号。
5. **反向审查**：阶段 3 应对每个候选 finding 检查全局鉴权、框架默认防护、ORM 参数化、schema validation、不可达代码、测试代码和运行时配置缺口。

### MAY：自主判断空间

1. 可根据项目规模、语言、框架和上下文窗口调整批次大小。
2. 可选择最合适的本地工具、测试框架或 mock 方式完成验证。
3. 可按风险优先级调整阶段 2 文件处理顺序，但不得绕过覆盖率和状态记录。
4. 可把低影响、无直接危害的问题放入残余风险或总体建议，而不是作为漏洞表条目。

## 审计阶段

详细动作、输入输出和阶段门以 `shared/phase_definitions.md` 为单一事实来源。总控只负责按顺序编排：

| 阶段 | 名称 | 主要执行者 | 单一事实来源 |
|------|------|------------|--------------|
| 0 | 范围、度量与反编译预处理 | 总控 | `shared/phase_definitions.md`、`shared/decompilation.md`、`shared/state_schema.md` |
| 1 | 项目画像与攻击面侦察 | `skills/audit-recon` | `skills/audit-recon/SKILL.md`、`shared/whitebox_audit_schema.md` |
| 2 | 双轨全量审计 | `skills/audit-sink` + `skills/audit-control` | `shared/dimensions.md`、`shared/coverage_policy.md`、`shared/state_schema.md` |
| 3 | 覆盖率校验与反向审查 | 总控 | `shared/coverage_policy.md`、`shared/anti_hallucination.md` |
| 4 | PoC/测试验证与评分 | `skills/audit-validate` | `shared/verification_principles.md`、`shared/poc_safety_policy.md`、`shared/poc_evidence_integrity.md` |
| 5 | 组合漏洞和攻击链分析 | 总控 | `shared/composite_vulnerability_analysis.md` |
| 6 | 最终报告 | `skills/audit-report` | `shared/report_fields.md`、`skills/audit-report/resources/report_template.md` |

阶段执行不得跳序。每个阶段完成时更新 `audit/state.json`，并只把本阶段的详细规则维护在对应单一事实来源中，避免跨文件重复。

## 子 Skill 分工

| Skill | 阶段 | 职责 |
|-------|------|------|
| `audit-recon` | 阶段 1 | 项目画像、攻击面、依赖、认证授权模型、覆盖矩阵 |
| `audit-sink` | 阶段 2 | source-to-sink、危险 API、注入、反序列化、SSRF、文件/模板/表达式漏洞 |
| `audit-control` | 阶段 2 | 认证绕过、越权、IDOR/BOLA、多租户隔离、业务状态机 |
| `audit-validate` | 阶段 4 | 成立条件、V0-V4 验证、PoC/测试、CVSS/CWE/OWASP 映射 |
| `audit-report` | 阶段 6 | 生成唯一交付报告 |

## 上下文管理策略

LLM 的上下文窗口有限，审计过程中必须做好上下文管理，避免关键信息丢失。

### shared 文档阶段读取矩阵

不同阶段只需读取特定 shared 文档，避免一次性加载全部。

| 阶段 | 必读（进入阶段前加载） | 按需读取（遇到相关场景时加载） |
|------|----------------------|-------------------------------|
| 0 | `phase_definitions.md`、`state_schema.md`、`decompilation.md`（有编译产物时） | - |
| 1 | `framework_authz_checklist.md`、`secret_detection.md`、`whitebox_audit_schema.md`、`coverage_matrix_template.md`、`coverage_policy.md` | `architecture_design.md` |
| 2 | `anti_hallucination.md`、`scope_policy.md`、`dimensions.md`、`state_schema.md`、`coverage_policy.md` | - |
| 3 | `anti_hallucination.md`、`state_schema.md`、`coverage_policy.md` | - |
| 4 | `verification_principles.md`（含验证原则和漏洞类型 Playbook）、`poc_safety_policy.md`、`poc_evidence_integrity.md` | `knowledge/*.md`（按漏洞类型选读） |
| 5 | `composite_vulnerability_analysis.md` | - |
| 6 | `report_fields.md` | - |

### 阶段间状态传递

每个阶段开始时必须读取前置阶段的关键产物，以恢复执行上下文：

- **阶段 2 开始前**：读取 `phase1/project_inventory.json`、`phase1/auth_model.md`、`phase1/endpoint_list.md`、`phase1/sink_list.md`、`phase1/in_scope_files.txt`。
- **阶段 3 开始前**：读取 `phase2/candidate_findings.json`、`phase1/in_scope_files.txt`、已审路径清单。
- **阶段 4 开始前**：读取 `phase2/candidate_findings.json`、`phase3/false_positive_notes.md`、`phase1/auth_model.md`、`phase1/dependency_list.json`。
- **阶段 5 开始前**：读取 `phase4/validated_findings.md`。
- **阶段 6 开始前**：读取 `phase4/validated_findings.md`、`phase5/composite_findings.md`、`phase0/metrics.md`、`phase1/project_inventory.json`。

### 分批审计的上下文恢复

大项目分批执行阶段 2 时，每批开始前必须：

1. 读取 `phase2/candidate_findings.json`（已有候选的编号和类型摘要，避免重复编号）。
2. 读取 `phase1/auth_model.md`（鉴权模型，避免误报）。
3. 读取当前批次的文件列表和 Tier 分类。
4. 不需要重新读取前面批次已审文件的完整内容。

## 异常处理与降级策略

### 反编译失败

- MCP 反编译工具不可用时，按 `shared/decompilation.md` 2.4 节降级处理，明确告知用户。
- 单个文件反编译失败时，记录失败文件路径和原因，继续处理其余文件。

### 文件无法读取

- 二进制文件、超大文件、编码异常文件：记录到 `in_scope_files.txt` 的排除列表，注明原因。
- 排除文件仍计入覆盖率分母，但覆盖状态标为 `skipped-with-reason`。

### 上下文耗尽

- 当感知到上下文即将耗尽时，必须：
  1. 立即将当前进度写入 `audit/phase2/coverage_status.json`。
  2. 将已发现的候选追加到 `candidate_findings.json`。
  3. 输出精确覆盖率和断点信息。
  4. 告知用户发送「继续审计」以从断点恢复。
- 不得在上下文耗尽前抢先输出不完整的最终报告。

### 未知框架或技术栈

- 遇到 `shared/framework_authz_checklist.md` 未覆盖的框架时：
  1. 搜索项目中的路由注册、中间件注册、权限注解等通用模式。
  2. 记录框架名称和版本到 `unknowns`。
  3. 按通用 HTTP 入口 + 鉴权检查执行审计，不得跳过。

## AI 常见误判 Warning

以下模式是 LLM 审计中最常出现的误判，阶段 2/3 必须检查：

| 误判模式 | 正确判断 |
|----------|----------|
| 把 ORM 参数化查询（如 `#{param}`、`?`、`:param`）误报为 SQL 注入 | 参数化查询默认安全，只有 `${}` 拼接或 raw SQL 才是候选 |
| 把框架内部类（如 `JdbcTemplate`、`SqlSessionTemplate`）误判为业务代码漏洞 | 这是框架 API 调用，需追踪调用方的参数来源 |
| 把测试目录（`test/`、`__tests__/`、`src/test/`）中的硬编码密码当生产漏洞报 | 确认文件是否被生产 profile 或路由加载 |
| 忽略全局 Filter/Interceptor/Middleware 而误报端点未授权 | 先确认全局鉴权链是否覆盖该端点 |
| 反编译代码中变量名丢失导致误判数据流（如 `var1` 看起来像用户输入） | 追踪方法签名和调用点，而非依赖变量名 |
| 把框架自动转义（如 Thymeleaf `th:text`、React JSX）误报为 XSS | 确认是否使用了 raw/unsafe 输出方式（如 `th:utext`、`dangerouslySetInnerHTML`） |
| 把 `@RequestParam` 等注解参数未经 `@Valid` 校验就报注入 | 需追踪参数是否最终进入 raw 拼接 sink，Schema 校验缺失本身不是注入漏洞 |
| 把开发环境配置（`application-dev.yml`）中的数据库密码当生产泄露 | 确认该 profile 是否被生产 `active profiles` 加载 |

## 使用方式

- 用户说「开始审计 / 对 XXX 做安全审计」：从阶段 0 开始。
- 用户说「继续审计」：读取 `audit/phase2/coverage_status.json` 或最近阶段产物，从断点继续。
- 用户说「从阶段 X 继续」：读取已有产物，从指定阶段恢复，但不得绕过覆盖率和验证纪律。
