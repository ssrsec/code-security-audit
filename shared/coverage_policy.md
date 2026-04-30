# 覆盖率策略

覆盖率必须可解释、可复算、可恢复。禁止用单一数字掩盖不同深度的审计动作。

## 0. 10 个安全审计维度

由 AI 根据项目类型决定审计顺序与深度。

| # | 维度 | 覆盖内容 |
|---|------|----------|
| D1 | 注入 | SQL 注入、命令注入、LDAP 注入、SSTI、SpEL、JNDI、模板注入 |
| D2 | 认证 | Token/Session/JWT/Filter 链/登录逻辑 |
| D3 | 授权 | CRUD 权限一致性、IDOR、水平/垂直越权 |
| D4 | 反序列化 | Java/Python/PHP 不安全反序列化 |
| D5 | 文件操作 | 上传/下载/路径遍历/任意读写 |
| D6 | SSRF | URL 注入、协议限制、内网探测 |
| D7 | 加密与凭据 | 硬编码密钥/凭据、弱加密算法（仅可直接利用的） |
| D8 | 配置 | Actuator/调试端点未授权、敏感信息泄露 |
| D9 | 业务逻辑 | 竞态条件、Mass Assignment、越权操作 |
| D10 | 供应链 | 依赖中已知高危 CVE |

### 双轨对应

- **Sink-driven**：D1 注入、D4 反序列化、D5 文件、D6 SSRF
- **Control-driven**：D2 认证、D3 授权、D8 配置、D9 业务逻辑

## 1. 三层覆盖率

最终报告和阶段状态必须分别记录三层覆盖率：

| 指标 | 含义 | 完成条件 |
|------|------|----------|
| 文件枚举覆盖率 | 授权范围内应审文件是否已完整列入分母 | `in_scope_files.txt` 覆盖全部应审文件，并记录排除理由 |
| 静态扫描覆盖率 | 应审文件是否已按 Tier 规则完成搜索、索引或结构扫描 | 每个文件都有扫描状态和证据 |
| 高风险深读覆盖率 | 命中入口、权限、sink、配置、回调、上传、下载、密钥等高风险文件是否已深读 | 高风险文件已读取相关上下文并记录结论 |

报告中可以给出总覆盖率，但必须说明它对应哪一层，不得把“静态扫描 100%”表述成“所有文件逐行深读 100%”。

## 2. Tier 覆盖标准

### T1：入口与控制层

Controller、Handler、路由、Filter、Interceptor、SecurityConfig、Gateway、MQ consumer、CLI、Job。

- 必须完整读取文件或足够覆盖所有入口的代码区间。
- 必须记录入口、参数来源、认证要求、授权要求、调用链起点。
- 必须检查是否命中 sink 或敏感业务能力。

### T2：业务与数据访问层

Service、DAO、Mapper、Repository、配置、模板、中间件封装。

- 先执行关键词、危险 API、权限函数、配置项和调用链扫描。
- 命中 sink、权限逻辑、租户过滤、文件操作、密钥处理时，升级为深读。
- 被 T1 调用链引用的关键 T2 文件必须按调用链上下文深读。

### T3：数据结构层

DTO、Entity、VO、Model、常量、纯类型定义。

- 做结构扫描和异常模式检查。
- 发现自定义序列化、敏感字段处理、业务逻辑、动态 getter/setter 时升级到 T2。

## 3. covered 判定

每个文件的状态只能是：

- `covered-deep`：已深读并记录安全结论。
- `covered-scan`：已按 Tier 规则扫描，未命中需深读模式。
- `skipped-with-reason`：不可读、二进制、第三方库、生成代码或明确出界，并记录原因。
- `pending`：尚未处理。

`skipped-with-reason` 计入分母，但必须在限制说明中披露。

## 4. OWASP Top 10 适用域一致性检查

文件覆盖率不是漏洞域覆盖率。阶段 3 计算覆盖率时，必须额外检查阶段 1/2 中是否出现 OWASP Top 10 适用域线索但最终没有对应候选 finding。

最低检查域按 OWASP Top 10 2021 映射：

- A01 Broken Access Control：未授权、越权、IDOR/BOLA、租户隔离、对象归属、批量操作、导出/下载/删除/配置接口。
- A02 Cryptographic Failures：弱哈希、弱随机、敏感数据明文、密钥/Token/连接串泄露、TLS/证书校验问题。
- A03 Injection：SQL/ORM/NoSQL/LDAP/XPath/命令/模板/表达式注入，动态代码执行，动态排序、筛选、批量 ID 和 raw query。
- A04 Insecure Design：审批、支付、退款、库存、状态机、风控、限流、幂等、业务前置条件缺失。
- A05 Security Misconfiguration：调试接口、错误回显、目录/静态资源暴露、默认配置、CSRF/CORS/Header 配置、危险数据库/中间件开关。
- A06 Vulnerable and Outdated Components：依赖版本、反序列化 gadget、已知 CVE、组件安全配置。
- A07 Identification and Authentication Failures：登录、找回密码、验证码、会话、SSO/OAuth/OIDC、JWT、API key、token 生命周期。
- A08 Software and Data Integrity Failures：不安全反序列化、文件上传与解析链、模板/插件/脚本更新、CI/CD 或供应链完整性。
- A09 Security Logging and Monitoring Failures：敏感操作审计缺失、认证失败/越权/管理操作无日志、日志中泄露敏感数据。
- A10 SSRF：URL fetch、代理、webhook、回调、图片/文档转换、FTP/HTTP/SOAP/SSH 外联。

如果某个适用域有线索但没有候选 finding，必须在既有的 `audit/phase3/false_positive_notes.md` 中增加该域的“未形成 finding 原因”，列出关键文件/入口、已观察防护点和排除证据。缺少这类说明时，不得把该域表述为已审无问题。

### RCE / 反序列化显式门禁

反序列化、动态代码执行、命令执行、模板/表达式执行不得被泛化为“已覆盖注入”后跳过。只要出现以下线索，必须逐项形成候选 finding、排除证据或阻塞项：

- 反序列化：`BinaryFormatter`、`ObjectInputStream`、`pickle`、`yaml.load`、`unserialize`、Fastjson/Jackson/XStream 多态反序列化、ViewState/LosFormatter、消息队列或缓存对象反序列化。
- 代码执行：`eval`、`exec`、动态编译、脚本引擎、反射调用、插件加载、动态 `Assembly.Load`、模板执行。
- 命令执行：`Process.Start`、`Runtime.exec`、`ProcessBuilder`、`child_process`、`os.system`、`subprocess`、shell 拼接、压缩/转换/Office/图片处理外部命令。

若未形成 finding，排除证据必须包含输入来源不可控性、允许列表/类型约束、危险 API 不可达性、sandbox/权限隔离或组件版本不受影响证明。

### 禁止截断覆盖数据

任何 OWASP Top 10 适用域线索不得只写前 N 条后继续推进。若线索数量大，必须沿用既有批次产物分批处理，并在 `audit/state.json` 或 `coverage_status.json` 记录总数、已处理数、未处理数。

## 5. 阶段门

- 阶段 4 前，文件枚举覆盖率和静态扫描覆盖率必须达到 100%。
- 高风险深读覆盖率必须达到 100%，否则不得验证相关 finding。
- 如果 `sink_list` 或 `endpoint_list` 中存在 OWASP Top 10 适用域线索，而最终候选没有对应漏洞，必须能在 `false_positive_notes.md` 或批次 findings 中复算排除原因。
- 若平台或上下文限制导致不能继续，写入 `audit/state.json` 并提示用户继续，不得提前生成最终报告。
