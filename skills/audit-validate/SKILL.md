---
name: audit-validate
description: 阶段 4 漏洞验证与评分。对候选 finding 执行 V0-V4 验证、PoC/测试生成、CVSS/CWE/OWASP 映射、误报剔除和修复建议。
---

# 漏洞验证（阶段 4）

## 角色

负责阶段 4：把阶段 2/3 的候选 finding 验证为“已确认”“待验证”或“不成立”。本阶段是质量门，不允许把未经验证的候选项直接写入最终报告。

## 输入

- `audit/phase2/candidate_findings.json`
- `audit/phase3/false_positive_notes.md`
- `audit/phase1/project_inventory.json`
- `audit/phase1/auth_model.md`
- `audit/phase1/framework_authz_map.md`
- `audit/phase1/dependency_list.json`
- `audit/phase1/secret_inventory.md`
- `audit/phase1/owasp_coverage_matrix.md`
- `shared/verification_principles.md`
- `shared/secret_detection.md`
- `shared/framework_authz_checklist.md`
- `shared/poc_safety_policy.md`
- `shared/poc_evidence_integrity.md`

## 验证等级

按 `shared/verification_principles.md` 使用 V0-V4：

- V0：代码线索，只能留在候选或残余风险。
- V1：静态可达，可作为待验证。
- V2：最小单元/函数级 PoC 验证。
- V3：本地集成/容器/服务级验证。
- V4：用户授权测试环境端到端验证。

最终报告中不得把 V0 写成漏洞。V1 必须明确未验证条件。V2-V4 需要记录命令、输入、预期、实际、清理步骤。

## 验证流程

### 1. 成立条件复核

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

### 3. PoC/测试生成

执行 PoC 前必须读取 `shared/verification_principles.md`（第二、三部分）、`shared/poc_safety_policy.md` 和 `shared/poc_evidence_integrity.md`，按漏洞类型满足最低验证证据并保存证据包。

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

### 4. CVSS/CWE/OWASP 映射

每条进入 `validated_findings.md` 的漏洞必须包含：

- CWE。
- OWASP Top 10。
- ASVS/WSTG。
- CVSS 向量、分数和每个指标理由。
- 严重性解释，避免只写分数。

### 5. 结论写入

- 已确认：写入 `audit/phase4/validated_findings.md`，验证状态 `已确认`。
- 待验证：写入 `validated_findings.md`，验证状态 `待验证`，必须列出待验证内容和限制。
- 不成立：写入 `audit/phase4/rejected_findings.md`，说明排除证据，不进入最终漏洞表。

验证结果同步写入 `audit/phase4/validation_results.json`，schema 参考 `shared/whitebox_audit_schema.md`。

## 重点漏洞验证提示

### 反序列化

- 查依赖版本和 classpath gadget。
- 查 safe mode、类型白名单、autoType、黑名单绕过。
- 若 source 来自 Redis/MQ/DB，继续查写入入口。
- 不能用“假如存在 gadget”作为已确认依据；找不到运行时条件时标待验证。
- 如果可执行代码路径成立，必须用无害命令输出、mock gadget 断言或测试日志证明执行结果。
- 按实际技术栈读取对应知识库：`fastjson_conditions.md`、`xstream_conditions.md`、`jackson_conditions.md`、`shiro_deserialization_conditions.md`、`snakeyaml_conditions.md`、`java_native_deserialization_conditions.md`、`python_pickle_conditions.md`、`php_unserialize_conditions.md`、`dotnet_deserialization_conditions.md`。

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
- 只证明“接口可访问”不够，必须证明访问结果突破认证或授权边界。

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

## 输出

- `audit/phase4/validated_findings.md`
- `audit/phase4/validation_results.json`
- `audit/phase4/rejected_findings.md`
- `audit/poc/<finding-id>/...`
