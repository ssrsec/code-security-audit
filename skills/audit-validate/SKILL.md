---
name: audit-validate
description: 阶段 4 单漏洞 V0-V4 验证与 PoC 评分。对 Phase 2 候选 finding 复核成立条件、生成 PoC、给出 CVSS/CWE/OWASP 映射、剔除误报、写入 validated_findings.md。不负责漏洞组合（→ audit-composite）、不负责原语组合（→ audit-composer-agent）。当 audit-orchestrator 进入 Phase 4 时触发。
---

# 阶段 4 单漏洞验证

## Banned Patterns（零容忍 — 出现即退回重写）

- 禁止：把 V0 / V1 漏洞写成「已确认」。
- 禁止：复现步骤出现 `REPLACE_XXX`、`REPLACE_WITH_VALID_XXX`、`YOUR_HOST`、`<!-- 此处替换为... -->`、`<root/>`、`此处从略`、`从略`、`细节略`、`不再展开`、`需按目标...编写` 等任何形式的占位。
- 禁止：CVSS 评分使用 "约"、"大约"、"≈" 等模糊词；必须输出完整 `CVSS:3.1/AV:.../A:X → X.X` 向量。
- 禁止：反序列化漏洞使用空壳 XML/JSON；必须按项目 classpath 实际依赖给出具体 gadget 链。
- 禁止：将高度确认的漏洞降级为"说明段落"或以"未单列 vul"回避；待验证漏洞必须进入报告。
- 禁止：用"假如存在 Gadget"作为已确认依据；找不到运行时条件时必须标待验证。
- 禁止：Python/Shell PoC 中出现 `...`（省略号）、`# TODO`、空 `pass`、不完整 import。
- 禁止：在本 skill 内执行漏洞组合分析（属于 `audit-composite` 职责）。

## 漏洞详情必填字段（缺一即退回）

每条写入 `validated_findings.md` 的漏洞必须含全部字段（按 `shared/report_fields.md`）：

1. **元信息表格**（Markdown 表）：漏洞编号、漏洞名称、漏洞描述、漏洞等级、验证状态、CVSS 完整向量、前置条件（术语全报告统一）、访问权限、调用链（href 中**严禁** `#L行号`）
2. **【复现步骤】**：真实数据包（Burp 格式），无占位
3. **【实战利用】**：至少 2 个含完整 payload 的场景
4. **【修复建议】**：具体文件 + 代码示例 + 修复原理
5. 验证状态为「待验证」时，表格中**必须**增加「待验证内容」行，逐条列出运行时验证项

## 角色

把阶段 2/3 候选 finding 验证为 **已确认 / 待验证 / 不成立**。本阶段是质量门，未经验证的候选不得直接进入最终报告。**只产出满足"漏洞"定义的条目，不产出"风险点"。**

## 输入

- `audit/phase2/candidate_findings.json`
- `audit/phase3/false_positive_notes.md`
- `audit/phase1/{project_inventory.json, auth_model.md, framework_authz_map.md, dependency_list.json, secret_inventory.md, coverage_matrix.md}`
- `shared/verification_principles.md`、`shared/poc_policy.md`（必读）
- `shared/secret_detection.md`、`shared/framework_authz_checklist.md`、`shared/sink_catalog_by_lang.md`（按需读取）

## 验证等级（V0-V4）

按 `shared/verification_principles.md`：

- V0：代码线索，只能留在候选或残余风险。
- V1：静态可达（HYPOTHESIS），可作为待验证。
- V2：最小单元/函数级 PoC 验证。
- V3：本地集成/容器/服务级验证（CONFIRMED）。
- V4：用户授权测试环境端到端验证（最高可信 CONFIRMED）。

最终报告中：V0 **不得**写成漏洞；V1 必须列明未验证条件；V2-V4 需要执行证据。

## 「已确认」与「待验证」判定（防漏报 — 严禁丢弃真实漏洞）

**核心原则：代码层面能高度确认存在危险模式的漏洞，必须进入报告。完美 payload 不是准入门槛。**

判定结果只有三种：

1. **已确认**：代码完整闭环，外部输入 → Sink，无有效防护。
2. **待验证**：代码高度确认危险模式存在，但部分利用条件需运行时验证 → **必须进入报告**。
3. **不成立**：仅当代码分析明确证明条件不可达（Sink 前有不可绕过的白名单校验等）。

**以下场景至少标「待验证」（严禁丢弃）：**

- 已知漏洞版本 + 危险 API 调用（Fastjson 1.2.7 `parseObject`、XStream 1.4.8 `fromXML` 无白名单等）
- 反序列化入口存在但 Gadget 链需运行时确认
- 注入拼接确认但具体 payload 需按 DB 方言微调
- 前端危险调用（如 `eval`）：代码中确实调用，危害取决于服务端返回是否可控

## 验证流程

### 1. 成立条件复核

按依赖版本与配置判断（必要时 `Read pom.xml/build.gradle/requirements.txt/package.json`、`Bash ls lib/ vendor/`）：

- `JSON.parseObject` → Fastjson 版本 + autoType/safeMode 配置
- `InitialContext.lookup` → JDK 版本（8u191 前后）
- `ObjectInputStream.readObject` → classpath 是否有可利用 Gadget（CommonsCollections / C3P0 / Rome 等）

按实际技术栈读取对应知识库：`fastjson_conditions.md`、`insecure_deserialization.md`、`auth_failures.md` 等。

**遇到陌生依赖 / 不确定 CVE 影响范围 / gadget 链不明 → 主动联网**：按 `shared/external_knowledge_protocol.md` §2 表 #2/#3/#5 查 NVD + 官方 advisory + 公开 PoC；至少 2 个独立来源相互印证才能升级为「已确认」；查询结果必须按 §4 格式留 URL 写入 finding 的「外部依据」字段。**禁止编造 CVE 编号或 gadget 名称。** 无搜索结果时标「待验证」+ 列出"需查 X"。

### 2. 反向审查（必须挑战每条 finding）

对每条 phase2 候选**按 `shared/sink_reachability_checklist.md` §1 R1-R7 复核**（sink 定义 / 被调用 / 生产加载 / 路由可达 / 全局拦截可绕过 / source 可控 / 运行时前提）。R 检查的额外重点：

- 全局鉴权是否覆盖；ORM 是否参数化；schema validation 是否约束参数（R5/R6）
- path normalize、白名单、MIME、扩展名是否不可绕过（R5/R6）
- 框架默认转义 / sandbox / safe mode 是否生效（R5）
- 测试代码或死代码是否被生产加载（R3）
- 攻击者能否拿到业务 ID / 租户 ID / token / 状态前置条件（R6）

**伪 sanitizer 复核**：按 `shared/taint_propagation.md` §2 四问 + §3 不消污规则识别 phase2 中可能被误判为"已清污"的节点（如把 base64 / urlencode / 长度判断当 sanitizer 的常见错误）。

只有代码或测试证据不能排除时，才保留为待验证。

### 3. 代码优先判定（深度验证，不浅尝辄止）

对每个"若 xxx"条件，必须先用 Read/Glob/Bash 判定，**不要写"需人工验证"逃避**：

- 限流 → Read 接口实现和配置
- 签名校验 → Read 回调处理逻辑
- 是否对外暴露 → Read 网关/路由配置
- **反序列化源**：数据来自 Redis/MQ 时，必须全局搜索向该 key/queue 写入的地方，验证攻击者是否可控

仅当代码中确实完全无法获知（如部署配置）时，才写"需人工验证"并注明原因。

### 4. 触发条件可行性评估

- **成立**：触发条件可达成 → 标「已确认」
- **部分成立**：代码层面高度确认但部分条件需运行时验证 → 标「待验证」并在「待验证内容」字段列出具体待确认项
- **不成立**：写入 `rejected_findings.md`，不进入报告

**「待验证」处理**：必须列出待确认项，例如：
- `① 需验证：攻击者是否可通过 SSRF 或缓存污染控制 parseObject 输入`
- `② 需验证：运行时 classpath 是否包含可利用 Gadget`
- `③ 需验证：实际 DB 方言（影响 payload 闭合方式）`

### 5. 参数与业务逻辑分析

"任意文件读取"、"IDOR"、"未授权访问某资源"类结论：

- 必须分析关键参数（configId/path/resourceId）的来源和约束
- UUID/仅授权可获知的参数不能直接下"任意 XXX"结论
- 标题和结论必须限定范围（如"文件读取（path 可控，存储 ID 待确认）"）

### 6. PoC / 测试生成

按 `shared/verification_principles.md` 第二、三部分 + `shared/poc_policy.md`，满足最低验证证据并保存证据包。

优先级：
1. 用户提供测试环境 → V4 端到端
2. 可本地运行 → V3 集成
3. 不可完整运行 → V2 单元/函数级 PoC
4. 缺少运行时条件 → V1 待验证 + 明确缺什么

PoC 通用要求：

- 无害、可清理、可复现。
- HTTP 漏洞写 `reproduce.http` 或报告内完整请求。
- 非 HTTP / 多步骤 / 协议类写完整脚本或测试。
- `{{access-token}}` 等运行时变量必须提供获取步骤。
- 必须记录实际输出：响应码、响应体关键字段、stdout/stderr、exit code、DB 返回、时间差、断言。
- 高危/严重漏洞必须生成 `audit/poc/<finding-id>/result.md` 或 `evidence.json`（执行时间、环境、命令/请求、实际输出、清理步骤、限制）。
- RCE/命令执行用无害命令：Linux/macOS `whoami`/`id`/`pwd`，Windows `whoami`/`cd`/`ver`。
- SQL 注入用只读证明：时间延迟、当前 DB 名/用户/版本，或 mock 断言最终 SQL；**禁止默认执行破坏性 SQL**。

正确的占位处理（不是禁止变量，是禁止"读者自行替换"）：

- Host 从项目配置读取，格式 `127.0.0.1:端口`
- 认证令牌用 `{{access-token}}`，但前置步骤写明获取方式（登录接口 + 默认账密）
- 业务 ID 在前置步骤说明获取接口，数据包用示例值（UUID）并标注"替换为步骤 N 获取的实际值"

### 7. 反序列化 payload 强制规则

按项目 classpath 实际存在的依赖构造**具体** payload：

- XStream：按版本号查 CVE，给完整 exploit XML
- Fastjson：按版本号给具体 `@type` 利用链（JdbcRowSetImpl + JNDI、TemplatesImpl 等），含完整 JSON
- Java 原生：按 classpath 中 commons-collections / commons-beanutils 等版本给对应 gadget 的 Base64 payload 或生成命令（ysoserial）

### 8. CVSS / CWE / OWASP 映射

每条进入 `validated_findings.md` 的漏洞必须包含：

- CWE
- OWASP Top 10
- ASVS / WSTG
- **完整 CVSS 3.1 向量**：`CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X → X.X`，每个指标附简要理由
- 不同条件下评分不同（如开/关认证），分别列出向量与分数

### 9. 结论写入

- 已确认 → `audit/phase4/validated_findings.md`（验证状态 `已确认`）
- 待验证 → 同文件（验证状态 `待验证`，含「待验证内容」与限制）
- 不成立 → `audit/phase4/rejected_findings.md`（排除证据，不进入报告）

结构化结果同步写 `audit/phase4/validation_results.json`，schema 见 `shared/whitebox_audit_schema.md`。

## 重点漏洞验证提示

### 反序列化

- 查依赖版本和 classpath gadget；查 safe mode、类型白名单、autoType、黑名单绕过。
- source 来自 Redis/MQ/DB → 继续查写入入口。
- 可执行代码路径成立 → 用无害命令输出/mock gadget 断言/测试日志证明执行结果。

### 注入

- 区分参数化查询与字符串拼接；动态表名/列名/排序字段也可能需要白名单。
- payload 与 DB 方言和上下文闭合匹配；无 DB 环境时用单元测试断言最终 SQL。
- SQL 注入验证须含基线 + 攻击请求；时间盲注须多次时间差或稳定测试断言。

### SSRF

- 查协议限制、内网 IP、重定向、DNS rebinding、IPv6、十进制/八进制/URL 编码。
- 验证影响：云 metadata、内网管理接口、回调服务、Redis/HTTP 内部接口。
- 无测试环境 → 本地 mock server 验证发起请求和绕过路径。

### 未授权 / 认证绕过

- 必须比较无认证/低权限请求 vs 高权限或合法请求。
- 记录预期（401/403/404/空）与实际（200/敏感字段/状态变更）。
- 只证明"接口可访问"不够，必须证明结果突破认证或授权边界。

### 敏感信息泄露

- 明确泄露类型：账号、密码、API key、JWT secret、私钥、连接串、session、PII、订单/支付数据、内部 URL、堆栈。
- 凭据/密钥优先验证可用性，报告展示必须脱敏。
- 普通版本号、非敏感路径、一般日志不默认进入漏洞表。
- 按 `shared/secret_detection.md`：生产可达性、服务对应、最小只读可用性、脱敏、轮换建议。

### 越权 / IDOR / BOLA

- 必须证明低权限用户能访问/操作不属于自己的资源。
- 无测试环境 → 服务层单元测试或 repository mock 证明缺少 owner/tenant 条件。
- 业务 ID 只有高权限可获得时应标明限制。

## 输出

- `audit/phase4/validated_findings.md`
- `audit/phase4/validation_results.json`
- `audit/phase4/rejected_findings.md`
- `audit/poc/<finding-id>/...`

> Phase 5 漏洞组合不在本 skill 范围。完成 Phase 4 后，由 `audit-composite/SKILL.md` 接管漏洞×漏洞的组合分析，由 `audit-composer-agent` 接管原语×原语的组合分析。
