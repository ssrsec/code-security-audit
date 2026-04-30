---
name: audit-validate
description: 阶段 4 漏洞验证与评分技能，同时承担漏洞级别的组合分析（Phase 5 漏洞组合轨道）。由 audit-orchestrator 在 Phase 4 调度，对 Phase 2 候选漏洞查阅知识库验证成立条件、执行 V0-V4 验证等级判定、PoC/测试生成、CVSS/CWE/OWASP 映射、误报剔除和修复建议，输出 validated_findings.md；Phase 5 继续执行**漏洞组合分析**，基于已确认/待验证漏洞发现组合攻击链，输出 composite_findings.md。**注意**：此技能只负责漏洞+漏洞的组合推理，原语（primitives）组合由 audit-composer-agent 在 Phase 5 并行负责，两者不交叉。只产出有实际危害的漏洞，不产出风险点。
---

# 漏洞验证（阶段 4）

## 角色

负责阶段 4：把阶段 2/3 的候选 finding 验证为"已确认""待验证"或"不成立"。本阶段是质量门，不允许把未经验证的候选项直接写入最终报告。**只产出满足"漏洞"定义的条目，不产出"风险点"。**

## 输入

- `audit/phase2/candidate_findings.json`
- `audit/phase3/false_positive_notes.md`
- `audit/phase1/project_inventory.json`
- `audit/phase1/auth_model.md`
- `audit/phase1/framework_authz_map.md`
- `audit/phase1/dependency_list.json`
- `audit/phase1/secret_inventory.md`
- `audit/phase1/coverage_matrix.md`
- `shared/verification_principles.md`
- `shared/secret_detection.md`
- `shared/framework_authz_checklist.md`
- `shared/poc_policy.md`

## 极致降噪与验证纪律（严禁漏报）

- 你是最终质量关卡，**但绝对不允许在不阅读完整代码/路由的情况下，主观漏报高危漏洞**。
- 例如：未授权访问（如可直接创建管理员账户的接口）、越权等，必须全盘分析所有在阶段 2 中发现的候选项。
- **验证必须在本阶段完成**：绝不允许说出"可先生成报告，后续再验证版本/端口"这样的话。如果需要读代码、找版本号、看配置文件，必须在当前阶段 4 中立即通过工具（Read/Glob/Bash）去执行。验证不完，就不能进入阶段 6。

## 「已确认」与「待验证」判定（严禁丢弃真实漏洞）

**核心原则：代码层面能高度确认存在危险模式的漏洞，必须进入报告。完美 payload 不是准入门槛。**

判定结果只有三种：
1. **已确认**（标记 `已确认`）：从代码完整闭环，外部输入 → Sink，无有效防护
2. **待验证**（标记 `待验证`）：代码高度确认危险模式存在，但部分利用条件需运行时验证 → **必须进入报告**
3. **不成立**（丢弃）：仅当代码分析明确证明条件不可达（如 Sink 前有不可绕过的白名单校验）

**以下场景必须至少标「待验证」进入报告，严禁丢弃**：
- **已知漏洞版本 + 危险 API 调用**：如 Fastjson 1.2.7 的 `parseObject`、XStream 1.4.8 的 `fromXML` 无白名单 —— 即使数据流来自内部服务/缓存/DB，攻击者仍可能通过 SSRF、缓存污染、中间人等控制数据源
- **反序列化入口存在但 Gadget 链需运行时确认**：classpath 有可疑依赖但无法 100% 确认
- **注入拼接确认但具体 payload 需按 DB 方言微调**
- **前端危险调用**（如 `eval`）：代码中确实调用了，只是危害程度取决于服务端返回是否可控

**⚠️ 绝对禁止**：
- 将高度确认的漏洞降级为"说明段落"放在摘要中（如"Fastjson 反序列化说明（未单列 vul 的原因）"）
- 因为无法提供完美 payload 就丢弃整条漏洞
- 因为"数据来自内部可信源"就排除 —— 内部源可能被其他漏洞污染

## 验证等级

按 `shared/verification_principles.md` 使用 V0-V4：

- V0：代码线索，只能留在候选或残余风险。
- V1：静态可达（HYPOTHESIS），可作为待验证。
- V2：最小单元/函数级 PoC 验证。
- V3：本地集成/容器/服务级验证（CONFIRMED）。
- V4：用户授权测试环境端到端验证（最高可信 CONFIRMED）。

最终报告中不得把 V0 写成漏洞。V1 必须明确未验证条件。V2-V4 需要记录命令、输入、预期、实际、清理步骤。

## 验证流程

### 1. 成立条件复核

阅读 `resources/knowledge/` 下对应文档，结合项目**依赖版本与配置**判断是否成立：

- 发现 `JSON.parseObject` → 查 Fastjson 版本与 autoType/safeMode 配置
- 发现 `InitialContext.lookup` → 查 JDK 版本（8u191 前后差异）
- 发现 `ObjectInputStream.readObject` → 查 classpath 中是否有可利用 Gadget

若无法从构建文件获取版本，扫描依赖目录（lib/、WEB-INF/lib/、node_modules/ 等）从文件名提取。

对每条候选 finding 检查：
- 外部输入是否可达入口。
- 访问权限是否真实可获得。
- source-to-sink 或控制缺失是否闭环。
- 防护点是否存在且是否有效。
- 依赖版本、配置、classpath、运行模式是否支持漏洞条件。
- 影响是否超出正常业务权限。

### 2. 反向审查

必须挑战 finding：
- 全局鉴权是否覆盖。
- ORM 是否参数化。
- schema validation 是否约束参数。
- path normalize、白名单、MIME、扩展名是否不可绕过。
- 框架默认转义/sandbox/safe mode 是否生效。
- 测试代码或死代码是否被生产加载。
- 攻击者能否拿到业务 ID、租户 ID、token、状态前置条件。

只有代码或测试证据不能排除时，才保留为待验证。

### 3. 代码优先判定（深度验证）

对每个"若xxx"条件，必须先通过 Read/代码追踪判定，**不要浅尝辄止，要顺着线索深入验证环境和上下文**：
- 限流 → Read 接口实现和配置
- 签名校验 → Read 回调处理逻辑
- 是否对外暴露 → Read 网关/路由配置
- **反序列化源** → 如果数据来自 Redis/MQ，必须通过全局搜索/Read 寻找向该 Redis key 或 MQ 队列写入数据的地方，验证攻击者是否能控制写入

仅当代码中确实完全无法获知（如部署配置）时，才写"需人工验证"并注明原因。见 `shared/verification_principles.md`。

### 4. 触发条件可行性评估

对每条发现评估：
- **成立**：触发条件可达成 → 标「已确认」
- **部分成立**：代码层面高度确认但部分条件需运行时验证 → 标「待验证」并在「待验证内容」字段列出具体待确认项
- **不成立**：代码分析明确证明条件不可达 → 写入 `rejected_findings.md`，不进入报告

**「待验证」处理（关键）**：标「待验证」时，必须在漏洞详情中增加**「待验证内容」**字段，逐条列出需要在实际部署环境中验证的具体事项，例如：
- `① 需验证：攻击者是否可通过 SSRF 或缓存污染控制 parseObject 的输入数据`
- `② 需验证：运行时 classpath 是否包含可利用的 Gadget 依赖`
- `③ 需验证：实际 DB 方言为 MySQL/Oracle/DM 中的哪种（影响注入 payload 闭合方式）`

### 5. 参数与业务逻辑分析

对"任意文件读取"、"IDOR"、"未授权访问某资源"类结论：
- 必须分析关键参数（configId/path/resourceId）的来源和约束
- UUID/仅授权可获知的参数不能直接下"任意XXX"结论
- 标题和结论必须限定范围（如"文件读取（path 可控，存储 ID 待确认）"）

### 6. PoC/测试生成

执行 PoC 前必须读取 `shared/verification_principles.md`（第二、三部分）和 `shared/poc_policy.md`，按漏洞类型满足最低验证证据并保存证据包。

优先级：
1. 用户提供测试环境：执行 V4 端到端验证。
2. 可本地运行：执行 V3 集成验证。
3. 不可完整运行：写最小化 V2 单元测试或函数级 PoC。
4. 缺少运行时条件：保留 V1 待验证，并明确缺少什么。

PoC 要求：
- 无害、可清理、可复现。
- HTTP 漏洞写 `reproduce.http` 或报告内完整请求。
- 非 HTTP、多步骤或协议类漏洞写完整脚本或测试。
- 使用 `{{access-token}}` 这类运行时变量时，必须提供获取步骤。
- 禁止 `REPLACE_XXX`、`TODO`、省略号、`此处从略` 等空洞占位。
- 必须记录实际输出：响应码、响应体关键字段、stdout/stderr、exit code、数据库返回、时间差、日志或测试断言。
- 高危/严重漏洞必须生成 `audit/poc/<finding-id>/result.md` 或 `evidence.json`，记录执行时间、环境、命令/请求、实际输出、清理步骤和限制。
- RCE/命令执行使用无害命令证明，如 Linux/macOS 的 `whoami`、`id`、`pwd`，Windows 的 `whoami`、`cd`、`ver`。
- SQL 注入使用只读证明，如时间延迟、当前数据库名、当前用户、版本或 mock 断言最终 SQL；禁止默认执行破坏性 SQL。

**反占位符强制规则（零容忍）**：
- `REPLACE_XXX`、`REPLACE_WITH_VALID_XXX`、`YOUR_HOST` 等任何要求读者自行替换的标记
- `<!-- 此处替换为... -->`、`<root/>` 等用注释或空标签伪装的占位
- `此处从略`、`从略`、`细节略`、`不再展开`、`需按目标...编写` 等推迟编写话术
- **一旦发现以上任何形式，该漏洞条目必须退回重写，不得进入 validated_findings.md**

**正确做法**：
- Host 从项目配置读取，格式 `127.0.0.1:端口`
- 认证令牌用 `{{access-token}}`，但必须在前置步骤写明获取方式（登录接口 + 默认账号密码）
- 业务 ID 在前置步骤说明获取接口，数据包中使用示例值（如 UUID 格式）并标注"替换为步骤 N 获取的实际值"

**反序列化漏洞 payload 强制规则**：
- 发现反序列化漏洞时，**必须根据项目 classpath 中实际存在的依赖**构造具体 payload，不得使用空壳 XML/JSON
- XStream：根据版本号（如 1.4.8）查找对应 CVE，给出该 CVE 的完整 exploit XML
- Fastjson：根据版本号（如 1.2.7）给出具体的 `@type` 利用链（如 JdbcRowSetImpl + JNDI、TemplatesImpl 等），包含完整的 JSON payload
- Java 原生反序列化：根据 classpath 中的 commons-collections/commons-beanutils 等版本给出对应 gadget 链的 Base64 编码 payload 或生成命令（如 ysoserial 命令）

**脚本完整性强制规则**：
- Python 脚本中严禁出现 `...`（省略号）、`# TODO`、`pass` 占位、或任何不完整的代码片段
- 必须包含所有 import 语句、完整的协议头/报文构造、正确的编码处理

### 7. CVSS/CWE/OWASP 映射

每条进入 `validated_findings.md` 的漏洞必须包含：

- CWE。
- OWASP Top 10。
- ASVS/WSTG。
- **必须输出完整的 CVSS 3.1 向量字符串**，格式为 `CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X → X.X`
- **严禁使用"约"、"大约"、"≈"等模糊近似词**。每个指标的选择必须附带简要理由。
- 若同一漏洞在不同条件下有不同评分（如开启/关闭认证），分别列出两个完整向量字符串及对应分数。

### 8. 结论写入

- 已确认：写入 `audit/phase4/validated_findings.md`，验证状态 `已确认`。
- 待验证：写入同一文件，验证状态 `待验证`，必须列出待验证内容和限制。
- 不成立：写入 `audit/phase4/rejected_findings.md`，说明排除证据，不进入最终漏洞表。

验证结果同步写入 `audit/phase4/validation_results.json`，schema 参考 `shared/whitebox_audit_schema.md`。

## 重点漏洞验证提示

### 反序列化

- 查依赖版本和 classpath gadget。
- 查 safe mode、类型白名单、autoType、黑名单绕过。
- 若 source 来自 Redis/MQ/DB，继续查写入入口。
- 不能用"假如存在 gadget"作为已确认依据；找不到运行时条件时标待验证。
- 如果可执行代码路径成立，必须用无害命令输出、mock gadget 断言或测试日志证明执行结果。
- **彻底抛弃"假如存在 Gadget"这种免责声明**。当发现反序列化时，必须亲自通过 Read 检查 `pom.xml`/`build.gradle`/`requirements.txt`/`package.json`，或通过 Bash ls 检查 `lib/`、`vendor/` 目录，明确找出项目中是否包含常见 Gadget 依赖（如 CommonsCollections、C3P0、Rome 等）。
- 按实际技术栈读取对应知识库：`fastjson_conditions.md`、`insecure_deserialization.md`、`auth_failures.md` 等。

### 注入

- 区分参数化查询与字符串拼接。
- 动态表名、列名、排序字段也可能需要白名单。
- payload 要与数据库方言和上下文闭合方式匹配。
- 没有数据库环境时，可用单元测试断言最终 SQL/查询对象。
- SQL 注入验证必须包含基线请求和攻击请求；时间盲注要至少记录多次时间差或稳定测试断言。

### SSRF

- 检查协议限制、内网 IP、重定向、DNS rebinding、IPv6、十进制/八进制/URL 编码。
- 验证影响：是否能访问云 metadata、内网管理接口、回调服务、Redis/HTTP 内部接口。
- 无测试环境时，用本地 mock server 验证发起请求和绕过路径。

### 未授权访问 / 认证绕过

- 必须比较无认证/低权限请求与高权限或合法请求。
- 记录预期安全行为（401/403/404/空数据）与实际行为（200/成功码/敏感字段/状态变更）。
- 只证明"接口可访问"不够，必须证明访问结果突破认证或授权边界。

### 敏感信息泄露

- 明确泄露类型：账号、密码、API key、JWT secret、私钥、数据库连接串、session、PII、订单/支付数据、内部 URL、堆栈。
- 对凭据/密钥优先验证可用性，但报告展示必须脱敏。
- 仅普通版本号、非敏感路径或一般日志不默认进入漏洞表。
- 按 `shared/secret_detection.md` 验证：生产可达性、服务对应关系、最小只读可用性、脱敏展示和轮换建议。

### 越权/IDOR/BOLA

- 需要证明低权限用户能访问或操作不属于自己的资源。
- 没有测试环境时，用服务层单元测试或 repository mock 证明缺少 owner/tenant 条件。
- 如果业务 ID 只有高权限可获得，应标明限制。

### 多接口组合利用

- 至少由两个已确认或待验证漏洞组成。
- 必须证明能力转移：第一个漏洞获得的数据、权限、网络可达性或文件如何成为第二个漏洞前置条件。
- 输出请求序列、关键响应、组合后影响和每一步验证等级。

## 漏洞详情必填字段

每条写入 `validated_findings.md` 的漏洞必须包含 `shared/report_fields.md` 中定义的**全部字段**：

- 漏洞详情信息必须使用 Markdown 表格展现（包括：漏洞编号、漏洞名称、漏洞描述、漏洞等级、验证状态、CVSS评分、前置条件、访问权限、调用链，超链接的 href 中严禁包含 `#L行号`，以防 IDE 跳转失败）
- 待验证漏洞必须增加「待验证内容」字段
- 【复现步骤】（真实数据包，严禁模板）、【实战利用】、【修复建议】

**缺少任何字段的漏洞不得进入报告。**

### 阶段 5：组合漏洞分析（阶段 4 完成后执行）

全部单漏洞验证完成后，按 `shared/composite_vulnerability_analysis.md` 执行漏洞组合分析：
- 检查是否存在漏洞 A 的输出可作为漏洞 B 的输入
- 检查是否存在"突破隔离"的组合（如 SSRF → 内网反序列化）
- 输出到 `audit/phase5/composite_findings.md`

## 知识库智能检索（含自学习沉淀）

每个知识库文件的 YAML 头部包含丰富的元数据（keywords、CWE、OWASP、frameworks、vuln_types），来源于 CWE Top 25 (2025)、OWASP Top 10、PayloadsAllTheThings (64k stars)、Nuclei-templates (12.1k stars) 等权威项目。

### 自动检索流程

验证每条候选漏洞时，按以下方式定位相关知识文档：

1. **CWE 精确匹配**：用 Grep 在 `resources/knowledge/` 目录搜索候选漏洞的 CWE ID（如 `CWE-89`），命中的文件优先阅读。
2. **漏洞类型匹配**：用 Grep 搜索 YAML 头中的 `vuln_types` 字段（如 `sql_injection`、`deserialization`）。
3. **关键词模糊匹配**：用 Grep 搜索 YAML 头中的 `keywords` 字段（如 `Fastjson`、`autoType`）。
4. **框架过滤**：根据项目技术栈，在 `frameworks` 字段中筛选（如只看 Java 相关文档）。

**查询示例**（Agent 直接执行 Grep）：
```bash
# 按 CWE 查找
rg "CWE-502" skills/audit-validate/resources/knowledge/ -l
# 按漏洞类型查找
rg "deserialization" skills/audit-validate/resources/knowledge/ -l
# 按框架过滤
rg "frameworks:.*Java" skills/audit-validate/resources/knowledge/ -l
```

或使用辅助脚本（可选）：
```bash
python3 scripts/knowledge_query.py --cwe CWE-89 --framework Java --json
```

### 参考优先级

1. 主知识库 `resources/knowledge/*.md`（人工审核 + 权威来源，高可信度）
2. 自学习目录 `resources/knowledge/learned/`（审计沉淀，供参考）

若 learned/ 中的模式与主知识库矛盾，以主知识库为准。

## DAST 动态验证（可选增强）

静态验证完成后，若环境中存在 DAST MCP Server（检查是否有 `dast_verify` 工具可用），可启用动态验证以提升 V1 漏洞的验证等级。

### 启用条件

1. 环境中有 DAST MCP Server（`dast_verify` 工具可用）。
2. 存在 V1 待验证漏洞。
3. 用户授权执行动态扫描。

### 执行流程

1. 从 V1 漏洞中筛选适合动态验证的候选（有明确端点、参数、注入点）。
2. 询问用户是否授权对目标环境执行 DAST。
3. 对每个候选调用 `dast_verify(finding_id, endpoint, method, vuln_type, payload_hints)`。
4. 合并结果：
   - DAST 确认 → 升级到 V3。
   - DAST 未触发 → 保持 V1（不降级，可能是检测限制）。
   - DAST 发现新漏洞 → 追加到 findings，回溯代码确认。

### 安全约束

- 禁止对生产环境执行 DAST（需用户确认环境类型）。
- 使用无害检测方式（时间盲注、布尔盲注），避免数据修改。
- DAST 结果仅辅助验证，最终判断仍由本 Agent 做出。

详细规范见 `shared/dast_integration.md`。

## 输出

- `audit/phase4/validated_findings.md`
- `audit/phase4/validation_results.json`
- `audit/phase4/rejected_findings.md`
- `audit/phase5/composite_findings.md`
- `audit/poc/<finding-id>/...`
- `audit/phase4/dast_results.json`（可选，DAST 启用时）
