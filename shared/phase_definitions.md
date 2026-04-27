# 审计阶段定义（阶段 0 - 6）

所有中间结果必须持久化到 `audit/`，不依赖 LLM 记忆。阶段必须严格按 **0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6** 线性执行，不允许提前生成最终报告，不允许跳过覆盖率校验和验证。

## 项目根与输出根

- 用户给定路径时以用户路径为项目根；否则以当前工作区根路径为项目根。
- 所有审计产出写入项目根下 `audit/`。
- 不得在执行中途随意切换到子模块目录。
- `audit/final/` 是最终证据包，阶段 6 完成后必须保留。

## 阶段 0：范围、度量与反编译预处理

**输入**：项目根路径、用户授权范围。

**动作**：

- 执行 `date "+%Y.%m.%d %H:%M:%S"` 获取审计开始时间并记录。
- 统计 LOC、文件数、模块数、入口数量、主要语言和构建系统。
- 使用 `find` 或等价工具实际扫描 `.class`、`.jar`、`.war`、`.dll` 等编译产物，严禁凭猜测声称不存在。
- 若发现编译产物且缺少对应源码，按 `shared/decompilation.md` 执行反编译。反编译输出视为审计源码继续进入阶段 1。
- 明确审计形态：`source_only`、`compiled_only`、`both`。无法判断时询问用户。

**输出**：

- `audit/phase0/metrics.md`
- `audit/phase0/scope.md`

## 阶段 1：项目画像与攻击面侦察

**输入**：阶段 0 产出、项目根路径、反编译输出路径（如存在）。

**动作**：

- 识别项目结构、开发语言、框架、中间件、构建系统、运行方式。
- 枚举 HTTP/RPC/WebSocket/MQ/CLI/任务调度入口。
- 分析认证逻辑、授权逻辑、租户隔离、资源归属校验、全局拦截链。
- 识别依赖版本、供应链风险、已知高危组件、潜在 gadget 依赖。
- 识别数据库、缓存、文件系统、对象存储、第三方服务和信任边界。
- 生成应审文件列表，作为覆盖率分母唯一来源。
- 生成端点清单、sink 清单、Tier 分类和 OWASP/ASVS/WSTG/CWE 覆盖矩阵。

**输出**：

- `audit/phase1/project_inventory.json`
- `audit/phase1/architecture_inventory.md`
- `audit/phase1/auth_model.md`
- `audit/phase1/in_scope_files.txt`
- `audit/phase1/tier_list.json`
- `audit/phase1/endpoint_list.md`
- `audit/phase1/sink_list.md`
- `audit/phase1/dependency_list.json`
- `audit/phase1/owasp_coverage_matrix.md`

## 阶段 2：全量审计（双轨）

**输入**：阶段 1 全部产物。

**动作**：

- **Sink-driven**：以 `sink_list.md`、依赖版本和危险配置为基准，从 sink 向上追踪外部输入，确认 source-to-sink 是否可达。
- **Control-driven**：以 `endpoint_list.md` 和 `auth_model.md` 为输入，检查认证、授权、租户隔离、资源归属、业务状态机和敏感操作。
- 对 T1 文件完整分析；T2/T3 先筛后读，但命中入口、sink、调用链、权限链时必须完整分析。
- 每个候选 finding 至少记录：入口、调用链、代码证据、防护点、疑似 CWE/OWASP 分类、验证等级 V0/V1、待验证条件。
- 大项目应分批执行，每批输出审阅清单和候选结果。

**输出**：

- `audit/phase2/findings_batch{N}.md`
- `audit/phase2/reviewed_paths_batch{N}.txt`
- `audit/phase2/candidate_findings.json`
- `audit/phase2/callchain_tracker.md`（跨文件调用链存在时必须维护）

## 阶段 3：覆盖率校验与反向审查

**输入**：阶段 2 审阅清单、阶段 1 应审文件列表、候选 findings。

**动作**：

- 精确计算覆盖率：已审文件数 / 应审文件数。禁止估算。
- 覆盖率未达到 100% 时，继续补扫未审文件，不得进入阶段 4。
- 对每个候选 finding 执行反向审查：
  - 全局鉴权/网关是否已经保护入口。
  - 框架、ORM、模板引擎是否默认防护。
  - schema validation、白名单、资源归属校验是否有效。
  - 是否测试代码、不可达代码、死代码或无外部触发路径。
  - 攻击前提是否现实。

**输出**：

- `audit/phase2/coverage_status.json`
- 更新 `audit/phase1/owasp_coverage_matrix.md`
- `audit/phase3/false_positive_notes.md`

## 阶段 4：漏洞验证、PoC/测试与评分

**输入**：阶段 2/3 候选 findings、依赖版本、配置、项目画像。

**动作**：

- 按 `shared/verification_principles.md` 对每条候选 finding 做 V0-V4 分级。
- 优先使用用户提供测试环境做 V4 端到端验证。
- 没有测试环境时，使用项目测试框架、mock、最小化单元测试或集成测试做 V2/V3。
- 对无法运行但静态证据完整的漏洞标记为待验证，并写明未验证条件；不得伪装成已确认。
- 对触发条件不成立的 finding 写入 rejected，不进入最终漏洞表。
- 为可评分漏洞输出 CVSS 向量、CWE、OWASP Top 10、ASVS/WSTG 映射。
- PoC 必须无害、可复现、包含清理步骤。

**输出**：

- `audit/phase4/validated_findings.md`
- `audit/phase4/validation_results.json`
- `audit/phase4/rejected_findings.md`
- `audit/poc/<finding-id>/...`

## 阶段 5：组合漏洞分析

**输入**：阶段 4 已确认和待验证漏洞。

**动作**：

- 按 `shared/composite_vulnerability_analysis.md` 分析漏洞组合。
- 重点识别 SSRF -> 内网服务、文件读 -> 密钥泄露、越权 -> 敏感数据、弱认证 -> 管理操作、依赖漏洞 -> 业务入口 等攻击链。

**输出**：

- `audit/phase5/composite_findings.md`

## 阶段 6：最终报告与证据包

**输入**：项目画像、覆盖矩阵、验证结果、PoC、组合漏洞。

**动作**：

- 按 `shared/report_fields.md` 生成 `audit/security_audit_report.md`。
- 复制或整理核心证据到 `audit/final/`，包括项目画像、覆盖矩阵、验证结果、PoC 索引和残余风险。
- 只清理临时批次碎片，例如临时草稿和重复批次文件。不得删除 `audit/decompiled`、`audit/poc`、`audit/final` 或最终报告。

**输出**：

- `audit/security_audit_report.md`
- `audit/final/project_inventory.json`
- `audit/final/owasp_coverage_matrix.md`
- `audit/final/validation_results.json`
- `audit/final/poc_index.md`
- `audit/final/residual_risk.md`
