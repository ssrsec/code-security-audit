---
name: audit-sink
description: 阶段 2 Sink-driven 审计。从危险 API、危险依赖和危险配置向上追踪 source-to-sink，发现注入、反序列化、SSRF、文件、模板、表达式、命令执行等漏洞候选。
---

# Sink-driven 审计（阶段 2）

## 角色

负责阶段 2 的 Sink-driven 轨道：从危险能力向上追踪输入来源，判断外部可控数据是否可达 sink，以及中途防护是否有效。此阶段输出候选 finding，不直接定性为最终漏洞。

## 输入

- `audit/phase1/sink_list.md`
- `audit/phase1/endpoint_list.md`
- `audit/phase1/dependency_list.json`
- `audit/phase1/project_inventory.json`
- `audit/phase1/auth_model.md`
- `audit/phase1/in_scope_files.txt`

## 必审 sink 域

| 域 | 典型 sink |
|----|-----------|
| 命令执行 | `Runtime.exec`、`ProcessBuilder`、`child_process.exec`、`os.system`、`subprocess` |
| 动态代码 | `eval`、`exec`、`vm.runInContext`、动态 import/include |
| 反序列化 | `ObjectInputStream.readObject`、Fastjson、XStream、Jackson polymorphic、pickle、yaml.load、PHP `unserialize` |
| 注入 | raw SQL/HQL/NoSQL/LDAP/XPath、字符串拼接查询、动态排序/字段名 |
| SSRF | URL fetch、代理、webhook callback、图片/文档转换、HTTP client |
| 文件 | 上传、下载、读取、写入、解压、路径拼接、对象存储 key |
| 模板/表达式 | SSTI、SpEL、OGNL、Velocity、FreeMarker、Handlebars、公式注入 |
| 加密/密钥/Secret | 硬编码账号密码、JWT secret、API key、云密钥、数据库连接串、弱随机数、JWT 签名绕过、禁用证书校验 |

## 硬门禁：OWASP Top 10 适用域不得漏审

以下不是新增输出标准，而是阶段 2 的一致性约束：只要项目存在 OWASP Top 10 适用域的 sink、入口、配置或依赖线索，就必须形成候选 finding、批次排除证据或阻塞项。SQLi 与文件上传只是 A03/A08 的典型样例，不能成为唯一强化对象。

本轨道重点负责 sink 相关域，并与 Control-driven 轨道共同覆盖完整 Top 10：

| OWASP Top 10 域 | Sink-driven 必查线索 |
|-----------------|----------------------|
| A02 Cryptographic Failures | 弱哈希、弱随机、明文敏感数据、密钥/Token/连接串、证书校验关闭 |
| A03 Injection | SQL/ORM/NoSQL/LDAP/XPath/命令/模板/表达式注入，动态代码执行，动态排序、筛选、批量 ID |
| A05 Security Misconfiguration | 调试/错误回显、目录暴露、CORS/Header/CSRF 配置、危险中间件开关 |
| A06 Vulnerable and Outdated Components | 依赖版本、已知 CVE、危险组件默认配置、反序列化 gadget |
| A08 Software and Data Integrity Failures | 文件上传与解析链、不安全反序列化、模板/插件/脚本更新、解压与导入链 |
| A10 SSRF | URL fetch、代理、webhook、回调、图片/文档转换、协议/IP/重定向控制 |

每条高风险线索必须形成明确结论：

- 外部输入可达且防护不足：进入 `candidate_findings.json`。
- 已确认参数化、白名单、类型强约束、路径规范化、组件版本不受影响或不可达：在批次 findings 或阶段 3 反向审查中写明排除证据。
- 上下文不足：写入 `audit/state.json` 或 `coverage_status.json` 的阻塞项，不得宣称该 Top 10 域完成。

示例检查点：

- A03 注入：`ExecuteNonQuery`、`ExecuteReader`、`ExecuteScalar`、`SqlCommand`、`CommandText`、`string.Format`、动态 `WHERE/ORDER BY/GROUP BY/IN`、DAO/Mapper raw query、命令执行、模板/表达式求值。
- A08 上传与完整性：`Request.Files`、`HttpPostedFileBase`、`IFormFile`、`multipart`、`SaveAs`、附件/图片/Office/模板/导入、扩展名/MIME/魔数校验、存储路径、下载/预览/解析/解压链。
- A10 SSRF：HTTP client、URL 参数、webhook callback、图片/文档转换、代理请求、协议白名单、内网 IP/DNS rebinding/重定向防护。
- A02 加密：MD5/SHA1、固定 salt、弱随机、硬编码密钥、Token 泄露、证书校验绕过。

### RCE / 反序列化显式门禁

反序列化、动态代码执行、命令执行是高危 sink，不得因为已覆盖 A03/A08 就省略逐项审计。

必须枚举并逐项处理：

- 反序列化：`BinaryFormatter`、`ObjectInputStream`、`pickle`、`yaml.load`、`unserialize`、Fastjson/Jackson/XStream 多态反序列化、ViewState/LosFormatter、缓存/MQ 对象反序列化。
- 代码执行：`eval`、`exec`、动态编译、脚本引擎、反射调用、插件加载、动态 `Assembly.Load`、模板执行。
- 命令执行：`Process.Start`、`Runtime.exec`、`ProcessBuilder`、`child_process`、`os.system`、`subprocess`、shell 拼接、压缩/转换/Office/图片处理外部命令。

每条线索必须形成明确结论：

- 外部输入或低权限可控数据可达危险 API 且防护不足：进入 `candidate_findings.json`。
- 输入不可控、类型白名单、sandbox、命令参数固定、路径/协议白名单或组件版本不受影响：在批次 findings 或阶段 3 反向审查中写明排除证据。
- 缺少调用链或运行配置上下文：写入 `audit/state.json` 或 `coverage_status.json` 的阻塞项，不得宣称 RCE/反序列化审计完成。

## 覆盖维度

本轨道负责以下安全维度（参考 `shared/dimensions.md`）：

| 维度 | 覆盖内容 |
|------|----------|
| D1 注入 | SQL 注入、命令注入、LDAP 注入、SSTI、SpEL、JNDI、模板注入 |
| D4 反序列化 | Java/Python/PHP 不安全反序列化 |
| D5 文件操作 | 上传/下载/路径遍历/任意读写 |
| D6 SSRF | URL 注入、协议限制、内网探测 |
| D7 加密与凭据 | 硬编码密钥/凭据、弱加密算法（仅可直接利用的） |
| D10 供应链 | 依赖中已知高危 CVE |

## 审计步骤

### 1. 定位 sink 上下文

- 先用 `rg` 定位符号，再读取相关代码上下文。
- 不得仅凭搜索结果报 finding。
- 大文件只读取相关行区间。
- 禁止只保留前 N 条搜索结果后继续推进。搜索结果过多时，按文件或模块分页处理，直到每条 sink 线索都有状态。

### 2. 逆向追踪 source-to-sink

从 sink 参数向上追踪到入口：

- HTTP/RPC/MQ/CLI/Job 参数。
- 数据库/缓存/MQ 的二次污染来源。
- 文件导入、上传文件内容、第三方回调内容。
- 配置项或环境变量是否可被低权限用户影响。

跨两个以上文件的调用链必须写入 `audit/phase2/callchain_tracker.md`。

### 3. 防护点判断

记录并验证：

- 参数化查询、白名单、schema validation、路径规范化。
- URL 协议/IP/重定向/DNS rebinding 防护。
- 反序列化 safe mode、类型白名单、classpath gadget。
- Secret 是否为示例值、是否被生产 profile 加载、是否可用于签名/登录/连接。
- 模板 sandbox、表达式白名单。
- 文件类型、MIME、扩展名、解压路径、对象存储 key 约束。

防护是否有效留给阶段 4 最终验证，但阶段 2 必须记录线索。

### 4. 候选 finding 输出

每条候选必须包含：

- finding id。
- sink 类型、文件:行号、代码证据。
- source 入口、参数名、访问权限。
- source-to-sink 调用链。
- 已观察到的防护点和疑似缺失点。
- 疑似 CWE、OWASP Top 10、ASVS/WSTG。
- 当前验证等级：V0 或 V1。
- 阶段 4 需要验证的条件。

建议同步写入 `audit/phase2/candidate_findings.json`，schema 参考 `shared/whitebox_audit_schema.md`。

### 4.1 Top 10 适用域负证据要求

即使没有发现漏洞，也必须为存在明确线索的 OWASP Top 10 适用域留下可复算的排除证据。优先写入当前批次的 `findings_batch{N}.md`；阶段 3 汇总到 `false_positive_notes.md`。

排除证据必须包含：

- 审计对象总数、已处理数、未处理数。
- 每个 sink/入口/配置/依赖线索的文件:行号、source、sink 或控制点、防护点、结论。
- 对被排除项的代码证据，例如参数化占位符、严格类型转换、白名单、路径规范化、扩展名/魔数校验、协议/IP 白名单、依赖版本不受影响证明。
- 若任何项未处理，必须记录阻塞项，并阻止阶段 4。

### 5. 降噪规则

以下情况不作为候选漏洞，但可在覆盖矩阵或误报说明中记录：

- 注释代码、测试代码、样例代码、不可达代码。
- 无外部可控 source 的内部常量或启动配置。
- 框架已强制参数化且没有 raw 拼接逃逸点。
- 文件路径完全由服务器端枚举或不可被用户影响。
- 仅 DoS、日志、header、cookie flag 等无直接权限或数据危害的问题。

但如果它们能与其他漏洞形成攻击链，应保留到阶段 5 分析。

## 进度要求

每批审计后：

- 追加已审路径到 `audit/phase2/reviewed_paths_batch{N}.txt`。
- 更新候选 findings。
- 汇报精确覆盖：`已审 X / 应审 Y = Z%`。
- 若 OWASP Top 10 适用域线索存在，按域汇报 `processed/total/pending`；pending 大于 0 时不得进入阶段 4。

## 输出

- `audit/phase2/findings_batch{N}.md`
- `audit/phase2/reviewed_paths_batch{N}.txt`
- `audit/phase2/candidate_findings.json`
- `audit/phase2/callchain_tracker.md`
