---
name: audit-validate
description: 阶段 4 单漏洞 V0-V4 验证与 PoC 评分。对 Phase 2 候选 finding 复核成立条件、生成 PoC、给出 CVSS/CWE/OWASP 映射、剔除误报、写入 validated_findings.md。不负责漏洞组合（→ audit-composite）、不负责原语组合（→ audit-primchain-agent）。当 audit-orchestrator 进入 Phase 4 时触发。
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
- 禁止：**循环论证前置条件** — 将漏洞的利用效果反过来作为触发该漏洞的前提条件（如"命令注入需要前提能在服务器上执行命令"、"SQL 注入需要数据库访问权限"、"文件读取需要文件系统访问"、"认证绕过需要管理员权限"）。前置条件只能描述攻击者利用漏洞之前已具备的能力（网络可达、已有身份、已知信息），详见 `shared/verification_principles.md` §5.1。
- 禁止：**敷衍式 PoC** — 复现步骤或实战利用中只有文字描述没有具体 Burp 数据包/payload/脚本代码（如"发送恶意请求即可触发"、"构造恶意序列化对象"这类空话）。
- 禁止：**PoC 认证级别与漏洞声明矛盾** — 漏洞标"无需认证"但 PoC 中携带认证令牌，或漏洞标"普通用户"但 PoC 使用管理员凭证。

## 漏洞详情必填字段

每条写入 `validated_findings.md` 的漏洞必须含全部字段（按 `shared/report_fields.md`）：

### V2-V4（已确认）字段要求

1. **元信息表格**：漏洞编号、名称、描述、等级、验证状态、CVSS 完整向量、前置条件、访问权限、调用链
2. **【复现步骤】**：真实数据包（Burp 格式），无占位，可直接复制使用
3. **【实战利用】**：场景数量按复杂度分级（复杂漏洞≥2个，简单漏洞1个即可，见 `shared/report_fields.md`）
4. **【修复建议】**：具体文件 + 代码示例 + 修复原理

### V1（待验证）字段要求

1. **元信息表格**：同上，但增加「待验证内容」行，逐条列出需运行时确认的条件
2. **【复现步骤】**：基于代码分析的最佳努力请求模板，标注哪些部分依赖待验证条件
3. **【可能的利用场景】**：至少 1 个假设验证通过后的利用方式（明确标注「以下基于假设 XXX 成立」）
4. **【修复建议】**：同上

**关键区别**：V1 不要求 payload 完全可用，但必须诚实标注不确定性。禁止把假设条件写成已确认事实。

## 角色

把阶段 2/3 候选 finding 验证为 **已确认 / 待验证 / 不成立**。本阶段是质量门，未经验证的候选不得直接进入最终报告。**只产出满足"漏洞"定义的条目，不产出"风险点"。**

## 输入

- `audit/phase0/config.json`（获取 mode / live_target / credentials）
- `audit/phase2/candidate_findings.json`
- `audit/phase3/false_positive_notes.md`
- `audit/phase1/{project_inventory.json, auth_model.md, framework_authz_map.md, dependency_list.json, secret_inventory.md, coverage_matrix.md}`
- `shared/verification_principles.md`、`shared/poc_policy.md`（必读）
- `scripts/tools/payload_templates/*.md`（按漏洞类型按需读取对应 payload 模板）
- `shared/secret_detection.md`、`shared/framework_authz_checklist.md`、`shared/sink_catalog_by_lang.md`（按需读取）

## 靶场集成验证（live_target 非 null 时启用）

当 `config.json` 中 `live_target` 存在时，验证行为升级：

### 验证流程

1. 代码分析确定攻击入口和 payload 结构
2. 读取 `scripts/tools/payload_templates/` 对应模板获取正确 payload 格式/命令
3. 构造真实 HTTP 请求（或其他协议请求）
4. 使用 Shell 工具发送请求到靶场（curl/httpie/python 脚本）
5. 捕获响应，记录为验证证据

### 代码与靶场结果不一致的判定

| 代码分析 | 靶场验证 | 判定 | 处理 |
|---------|---------|------|------|
| 确认可利用 | 成功复现 | V4 已确认 | 记录完整请求+响应 |
| 确认可利用 | 失败 | V2 代码层确认 | 标注「靶场环境差异」，保留代码证据，可能原因：版本不同/配置不同/WAF |
| 不确定 | 成功复现 | V4 已确认 | 以靶场结果为准，标注「经靶场验证确认」 |
| 不确定 | 失败 | V1 待验证 | 记录尝试过程，列出可能原因 |

### 靶场验证安全边界

- RCE 类：只执行无害命令（`id`/`whoami`/`pwd`）
- SQL 注入：只读操作（时间盲注/查版本/查当前用户）
- 文件操作：只读取已知安全文件（`/etc/hostname`、Web 根 index 等）
- 认证绕过：验证能访问即可，不进行破坏性操作

### 靶场 HTTP 请求实践指南

**多步骤验证模板**（需要先登录再测试的场景）：

```bash
# 步骤 1：登录获取 token/cookie
TOKEN=$(curl -sk -X POST "$LIVE_TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 步骤 2：用 token 请求目标接口
curl -sk "$LIVE_TARGET/api/admin/users" \
  -H "Authorization: Bearer $TOKEN" \
  -o response.json -w "\n%{http_code}"

# 步骤 3：无认证对比请求（验证未授权）
curl -sk "$LIVE_TARGET/api/admin/users" \
  -o response_noauth.json -w "\n%{http_code}"
```

**关键参数**：
- `-s`：静默模式
- `-k`：跳过 HTTPS 证书验证（靶场常见自签证书）
- `-o`：输出到文件便于后续分析
- `-w "\n%{http_code}"`：打印 HTTP 状态码
- `-b cookie.txt` / `-c cookie.txt`：Cookie 文件保持会话

**证据保存**：每次验证请求的完整请求头+响应头+响应体保存到 `audit/poc/<vul-id>/evidence.txt`

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
- **HTTP 漏洞必须使用 Burp 风格原始 HTTP 数据包格式**（请求行 + 请求头 + 空行 + 请求体，可直接粘贴到 Burp Repeater 发送）。禁止仅用 curl/httpie 命令替代。
- 非 HTTP / 多步骤 / 协议类写完整可执行脚本或测试（含所有 import，禁止省略号）。
- `{{access-token}}` 等运行时变量必须提供获取步骤（给出获取 token 的完整 Burp 数据包）。
- 必须记录实际输出：响应码、响应体关键字段、stdout/stderr、exit code、DB 返回、时间差、断言。
- 高危/严重漏洞必须生成 `audit/poc/<finding-id>/result.md` 或 `evidence.json`（执行时间、环境、命令/请求、实际输出、清理步骤、限制）。
- RCE/命令执行用无害命令：Linux/macOS `whoami`/`id`/`pwd`，Windows `whoami`/`cd`/`ver`。
- SQL 注入用只读证明：时间延迟、当前 DB 名/用户/版本，或 mock 断言最终 SQL；**禁止默认执行破坏性 SQL**。
- **前置条件必须通过反循环论证检查**（`shared/verification_principles.md` §5.1）：禁止将漏洞利用效果本身作为触发漏洞的前提。

正确的占位处理（不是禁止变量，是禁止"读者自行替换"）：

- Host 从项目配置读取，格式 `127.0.0.1:端口`
- 认证令牌用 `{{access-token}}`，但前置步骤写明获取方式（登录接口 + 默认账密）
- 业务 ID 在前置步骤说明获取接口，数据包用示例值（UUID）并标注"替换为步骤 N 获取的实际值"

### 7. Payload 生成规则

**按需读取 `scripts/tools/payload_templates/` 下对应语言/类型的模板文件**，获取正确的 payload 结构和生成命令。

输出要求：
- 直接给出可用的 payload（JSON/XML/Python 代码/SQL 语句等）
- 如果需要工具生成（如 Java 反序列化的 binary payload），给出完整的工具命令
- 标注 payload 适用的版本范围和前提条件
- 有靶场时直接嵌入请求发送验证；无靶场时作为报告中的复现步骤

各类型参考模板：
- Java 反序列化 → `payload_templates/java_deser_chains.md`
- Fastjson → `payload_templates/fastjson_payloads.md`
- XStream → `payload_templates/xstream_payloads.md`
- .NET 反序列化 → `payload_templates/dotnet_deser_chains.md`
- Python pickle/yaml → `payload_templates/python_deser.md`
- PHP 反序列化 → `payload_templates/php_deser_chains.md`
- SQL 注入 → `payload_templates/sqli_by_dialect.md`
- 模板注入 → `payload_templates/ssti_by_engine.md`
- SSRF 绕过 → `payload_templates/ssrf_bypass.md`

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

> Phase 5 漏洞组合不在本 skill 范围。完成 Phase 4 后，由 `audit-composite/SKILL.md` 接管漏洞×漏洞的组合分析，由 `audit-primchain-agent` 接管原语×原语的组合分析。
