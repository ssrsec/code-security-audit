# 审计阶段定义（阶段 0 - 6）

所有中间结果必须**持久化到文件**，不依赖 LLM 记忆。阶段必须严格按 **0 → 1 → 2 → 3 → 4 → 5 → 6** 线性执行，不允许提前生成最终报告，不允许跳过覆盖率校验和验证。

**阶段执行铁律：绝不允许"提前交付报告然后再去验证"，绝不允许跳过验证步骤，绝不允许擅自改变各个阶段的职责。**

**审计模式**：全量审计，禁止抽样。按阶段 1 产出的应审文件列表逐文件审阅直至覆盖率 100%，未达 100% 不得进入阶段 4。

---

## 项目根与输出根

- 用户给定路径时以用户路径为项目根；否则以当前工作区根路径为项目根。
- 所有审计产出写入项目根下 `audit/`。
- 长流程状态写入 `audit/state.json`，字段和恢复规则见 `shared/state_schema.md`。
- 不得在执行中途随意切换到子模块目录。
- 阶段 6 的唯一交付物是 `audit/security_audit_report.md`，最终报告必须内联关键结论、复现细节、前置条件、调用链和修复建议。

---

## 阶段 0：范围、度量与反编译预处理

**输入**：项目根路径、用户授权范围。

**动作**：

- 执行 `date "+%Y.%m.%d %H:%M:%S"` 获取审计开始时间并记录。
- 统计 LOC、文件数、模块数、入口数量、主要语言和构建系统。
- **编译产物扫描（必须执行）**：使用 `find` 或 `Glob` 实际扫描项目目录，确认是否存在 `.class`、`.jar`、`.war`、`.dll` 等编译产物。**严禁凭猜测声称"不存在"**。
- 若发现编译产物且缺少对应源码，按 `shared/decompilation.md` 执行反编译。反编译输出视为审计源码继续进入阶段 1。
  - Java 产物（.class/.jar/.war）→ 使用 `java-decompiler` MCP 工具反编译；`classes/` 目录全量反编译，`lib/` 目录按业务包名筛选反编译
  - ASP.NET DLL → 使用 `ilspy-mcp` MCP 工具反编译
  - MCP 工具不可用时按降级策略处理，严禁跳过
- 明确审计形态：`source_only`、`compiled_only`、`both`。无法判断时询问用户。

**输出**：

- `audit/phase0/metrics.md`（必须写入：审计开始时间、LOC、文件数；若执行了反编译还需写入审计形态、反编译工具、反编译输出路径）
- `audit/phase0/scope.md`

**⚠️ 阶段 0 仅负责度量与反编译预处理。反编译完成后，必须正常进入阶段 1 → 2 → 3 → 4 → 5 → 6，严禁跳过任何阶段。反编译只是将编译产物转换为源代码形态，后续流程与审计源代码项目完全一致。**

---

## 阶段 1：项目画像与攻击面侦察

**输入**：阶段 0 产出、项目根路径、反编译输出路径（如存在）。

**动作**：

- 识别项目结构、开发语言、框架、中间件、构建系统、运行方式。
- 枚举 HTTP/RPC/WebSocket/MQ/CLI/任务调度入口，产出端点/路由清单（必须包含登录/认证/导出相关端点）。
- 分析认证逻辑、授权逻辑、租户隔离、资源归属校验、全局拦截链，建立认证授权模型。
- 按 `shared/framework_authz_checklist.md` 分析框架级鉴权/授权配置。
- 识别依赖版本、供应链风险、已知高危组件、潜在 gadget 依赖。
- 按 `shared/secret_detection.md` 识别硬编码账号、密码、密钥、Token、连接串、证书。
- 识别数据库、缓存、文件系统、对象存储、第三方服务和信任边界。
- 生成应审文件列表，作为覆盖率分母唯一来源；执行 Tier 分类（T1/T2/T3）。
- 生成 Sink/危险 API 清单。
- 初始化 OWASP/ASVS/WSTG/CWE 覆盖矩阵；覆盖矩阵必须显式包含未授权/越权、敏感信息泄露、反序列化、注入、SSRF、文件、密钥与组合攻击链域。

**输出**：

- `audit/phase1/phase1_recon.md`（技术栈、入口、审计形态简报）
- `audit/phase1/project_inventory.json`（项目语言、框架、依赖、入口，结构化）
- `audit/phase1/architecture_inventory.md`（模块结构、数据流、信任边界）
- `audit/phase1/auth_model.md`（认证、授权、租户隔离模型）
- `audit/phase1/framework_authz_map.md`（框架级鉴权配置）
- `audit/phase1/in_scope_files.txt`（应审文件列表，覆盖率分母唯一来源）
- `audit/phase1/tier_list.json`（Tier 分类）
- `audit/phase1/coverage_matrix.md`（OWASP/ASVS/WSTG/CWE 覆盖矩阵）
- `audit/phase1/endpoint_list.md`（端点清单）
- `audit/phase1/sink_list.md`（危险 API 清单）
- `audit/phase1/dependency_list.json`（依赖清单）
- `audit/phase1/secret_inventory.md`（Secret 线索）

---

## 阶段 2：全量审计（双轨）

**输入**：阶段 1 全部产物。

**动作**：

- **Sink-driven**：以 `sink_list.md`、依赖版本和危险配置为基准，从 sink 向上追踪外部输入，确认 source-to-sink 是否可达。
- **Control-driven**：以 `endpoint_list.md` 和 `auth_model.md` 为输入，检查认证、授权、租户隔离、资源归属、业务状态机和敏感操作。优先级 P0（未认证可达）→ P1（低权限可达）→ P2（管理员专用）。
- **Interface-driven**：对所有公开、白名单、低权限、导出、下载、调试、日志、配置、备份、管理接口进行未授权访问和敏感信息泄露专项检查。
- 对 T1 文件完整分析；T2/T3 先筛后读，命中入口、sink、调用链、权限链时必须完整分析。
- 每个候选 finding 至少记录：入口、调用链、代码证据、防护点、疑似 CWE/OWASP 分类、验证等级 V0/V1、待验证条件。
- 记录 `primitives_batch{N}.md`（原语能力片段）：将可拼接攻击原语（任意读、任意写、SSRF 可达内网、代码执行等）独立记录，供组合漏洞分析使用。
- 覆盖率口径必须诚实：按 `shared/coverage_policy.md` 分别记录文件枚举覆盖率、静态扫描覆盖率和高风险深读覆盖率；不得把扫描覆盖表述成逐行深读。
- 执行 OWASP Top 10 适用域一致性检查：每个适用于当前项目的 Top 10 域只要存在入口、sink、配置、依赖或业务线索，就必须形成候选 finding 或留下排除证据；反序列化、动态代码执行、命令执行/RCE 线索必须显式处理，不得因线索过多而截断。
- 大项目应分批执行（>200 文件时每批 50-150），每批输出审阅清单和候选结果。

**输出**：

- `audit/phase2/findings_batch{N}.md`（候选漏洞列表）
- `audit/phase2/reviewed_paths_batch{N}.txt`（各批次审阅文件）
- `audit/phase2/reviewed_paths_merged.txt`（合并审阅清单）
- `audit/phase2/candidate_findings.json`（候选 finding 汇总）
- `audit/phase2/primitives_batch{N}.md`（各批次原语能力片段）
- `audit/phase2/callchain_tracker.md`（跨文件调用链存在时必须维护）

---

## 阶段 3：覆盖率校验与反向审查

**输入**：阶段 2 审阅清单、阶段 1 应审文件列表、候选 findings。

**动作**：

- 精确计算三层覆盖率（文件枚举覆盖率、静态扫描覆盖率、高风险深读覆盖率）。通过 `wc -l` 或严格计数统计具体行数，禁止估算。
- **完成度判定**：
  - 覆盖率 = 100% → 进入阶段 4
  - 覆盖率 < 100% → 自动执行下一批补扫，循环直到 100%；仅当平台限制无法继续时才停止，必须输出精确进度（如"当前进度：已覆盖 125/250 个文件，精确覆盖率 50.0%"），随后**只能**提示用户输入「继续审计」，绝不提供跳过流程或提前生成报告等任何其他选择。
- 执行报告一致性预检：若 `sink_list.md` 或 `endpoint_list.md` 中存在任一 OWASP Top 10 适用域线索（尤其是反序列化、动态代码执行、命令执行/RCE、注入、SSRF、认证授权等），而候选 finding 和批次/反向审查记录均未覆盖该域，不得进入阶段 4。
- 对每个候选 finding 执行反向审查：
  - 全局鉴权/网关是否已经保护入口
  - 框架、ORM、模板引擎是否默认防护
  - schema validation、白名单、资源归属校验是否有效
  - 是否为测试代码、不可达代码、死代码或无外部触发路径
  - 攻击前提是否现实

**输出**：

- `audit/phase2/coverage_status.json`（覆盖率状态）
- 更新 `audit/phase1/coverage_matrix.md`
- `audit/phase3/false_positive_notes.md`（反向审查与误报说明）

---

## 阶段 4：漏洞验证、PoC/测试与评分

**输入**：阶段 2/3 候选 findings、依赖版本、配置、项目画像。

**动作**：

- 按 `shared/verification_principles.md` 对每条候选 finding 做 V0-V4 分级。
- 代码优先判定每个"若 xxx"条件，不一律写"需人工验证"；对任意文件读取/IDOR 等必须分析参数来源与约束。
- 优先使用用户提供的测试环境做 V4 端到端验证；无测试环境时，使用项目测试框架、mock、最小化单元测试或集成测试做 V2/V3。
- 对无法运行但静态证据完整的漏洞标记为「待验证」，并写明未验证条件；**严禁因 payload 不完美而丢弃**，不得伪装成已确认。
- 对触发条件不成立的 finding 写入 rejected，不进入最终漏洞表。
- 为可评分漏洞输出 CVSS 向量、CWE、OWASP Top 10、ASVS/WSTG 映射。
- PoC 必须无害、可复现、包含清理步骤，满足 `shared/verification_principles.md` 第三部分（漏洞类型级 Playbook）的证据要求。
- 高危/严重漏洞必须有结果摘要或结构化证据，满足 `shared/poc_evidence_integrity.md` 的证据完整性要求。

**输出**：

- `audit/phase4/validated_findings.md`（已验证漏洞，与 phase3/findings_verified.md 结构对齐）
- `audit/phase3/findings_verified.md`（同步别名，含「已确认」和「待验证」两类）
- `audit/phase4/validation_results.json`
- `audit/phase4/rejected_findings.md`
- `audit/poc/<finding-id>/...`

---

## 阶段 5：组合漏洞分析（必须执行）

**输入**：阶段 4 已确认和待验证漏洞；阶段 2 各批次原语 `primitives_batch{N}.md`。

**动作**：

**轨道 A（漏洞组合，audit-validate-agent 继续执行）：**
- 按 `shared/composite_vulnerability_analysis.md` 分析漏洞组合；**必须基于本次审计已发现的至少 2 个漏洞进行组合**，不得用单个漏洞加前置条件充数。
- 重点识别攻击链：SSRF → 内网服务、文件读 → 密钥泄露、敏感信息泄露 → IDOR/越权、弱认证 → 管理操作、未授权导出 → 批量数据访问等。

**轨道 B（原语组合，audit-composer-agent 并行执行）：**
- 汇聚 `audit/phase2/primitives_batch{N}.md` 中所有原语，构建原语注册表。
- 按 `shared/primitive_chain_catalog.md` 规则表执行快速命中（CHAIN-RULE-NNN 匹配）。
- 未被规则命中的原语集，由 LLM 推理发现隐式组合链。
- 输出原语注册表和组合攻击链。

**输出**：

- `audit/phase5/composite_findings.md`（漏洞组合分析，**主路径**）
- `audit/phase3/composite_findings.md`（同步别名）
- `audit/phase5/primitive_registry.md`（所有原语汇总注册表）
- `audit/phase5/primitive_chains.md`（原语组合攻击链，无命中时写"未发现"）

---

## 阶段 6：最终报告

**输入**：项目画像、覆盖矩阵、验证结果、PoC、组合漏洞。

**动作**：

- 按 `shared/report_fields.md` 生成 `audit/security_audit_report.md`。
- 严格使用 `skills/audit-report/resources/report_template.md` 的五章节结构：一、项目代码审计总结；二、漏洞汇总表；三、漏洞详情；四、组合漏洞摘要；五、总体安全建议。
- 检查 OWASP Top 10 完整性：对每个标记为适用的域，确认报告中已覆盖或有排除理由。
- 最终报告只输出一份，所有复现细节、前置条件、调用链、修复建议必须直接展现在报告中，禁止引用中间过程文件作为正文替代。
- 每条漏洞满足全部必填字段方可输出。

**输出**：

- `audit/security_audit_report.md`（唯一交付物）
