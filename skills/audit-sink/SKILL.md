---
name: audit-sink
description: 阶段 2 Sink-driven 数据流审计技能。由 audit-orchestrator 在 Phase 2 与 audit-control 并行调度，从危险 API（exec/eval/反序列化/SQL拼接/文件操作）向上逆向追踪数据流，判断外部输入是否可达 Sink 且无有效过滤，发现 RCE/SQL注入/反序列化/SSRF/任意文件读写等漏洞候选。**同时输出 primitives_batch{N}.md 原语批次文件**（记录受约束的能力片段供 audit-composer-agent 做组合推理）。当 audit-orchestrator 进入 Phase 2 Sink-driven 轨道，或需要对特定 Sink 追踪数据流来源时触发。
---

# Sink-driven 审计（阶段 2）

## 角色

负责阶段 2 的 Sink-driven 轨道：从危险能力向上追踪输入来源，判断外部可控数据是否可达 sink，以及中途防护是否有效。**只记录有实际攻击路径的发现**，丢弃纯理论风险。此阶段输出候选 finding，不直接定性为最终漏洞。

## 输入

- `audit/phase1/sink_list.md`
- `audit/phase1/endpoint_list.md`
- `audit/phase1/dependency_list.json`
- `audit/phase1/project_inventory.json`
- `audit/phase1/auth_model.md`
- `audit/phase1/in_scope_files.txt`

## 漏报红线（严禁遗漏数据流漏洞）

- 必须完整追踪数据流，不能因为方法调用链较深就中途放弃。
- 绝不能主观臆断某些入口"不会被恶意用户调用"。只要从公网端点（或内部可达端点）能通过入参将污染数据传入 Sink，且未经过滤，必须作为候选漏洞上报。
- 任何形式的文件操作（上传、读取、写入）、执行层（SQL、命令执行、反序列化等），只要发现可疑数据流就必须记录候选。

## 极致降噪原则（严禁报告非漏洞项）

- **只报告能导致获取权限、数据泄露、篡改、系统被控的漏洞。**
- **严禁**将"整文件注释的死代码"、"配置文件存在但没有外部可控入口"、"使用了系统环境变量/启动参数"、"日志输出格式"当作漏洞报告——这些属于维护性或配置缺陷，根本没有攻击者可控的触发路径。
- 如果用户输入不可控（例如：只是框架自带功能、配置属性注入、重启函数没有绑定到 HTTP 等），则**直接无视并跳过，不要为其分配 findings 编号**。
- 不要报告代码规范问题、设计模式问题或"未来可能会被利用"的假设性场景。必须有**现实中的外部触发入口**。

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

以下是阶段 2 的一致性约束：只要项目存在 OWASP Top 10 适用域的 sink、入口、配置或依赖线索，就必须形成候选 finding、批次排除证据或阻塞项。

本轨道重点负责 sink 相关域，与 Control-driven 轨道共同覆盖完整 Top 10：

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
- 上下文不足：写入阻塞项，不得宣称该 Top 10 域完成。

**检查点示例**：

- A03 注入：`ExecuteNonQuery`、`ExecuteReader`、`CommandText`、`string.Format`、动态 `WHERE/ORDER BY/GROUP BY/IN`、DAO/Mapper raw query、命令执行、模板/表达式求值。
- A08 上传与完整性：`IFormFile`、`multipart`、`SaveAs`、附件/图片/Office/模板/导入、扩展名/MIME/魔数校验、存储路径、下载/预览/解析/解压链。
- A10 SSRF：HTTP client、URL 参数、webhook callback、图片/文档转换、代理请求、协议白名单、内网 IP/DNS rebinding/重定向防护。
- A02 加密：MD5/SHA1、固定 salt、弱随机、硬编码密钥、Token 泄露、证书校验绕过。

### RCE / 反序列化显式门禁

反序列化、动态代码执行、命令执行是高危 sink，不得因为已覆盖 A03/A08 就省略逐项审计。

必须枚举并逐项处理：

- 反序列化：`BinaryFormatter`、`ObjectInputStream`、`pickle`、`yaml.load`、`unserialize`、Fastjson/Jackson/XStream 多态反序列化、ViewState/LosFormatter、缓存/MQ 对象反序列化。
- 代码执行：`eval`、`exec`、动态编译、脚本引擎、反射调用、插件加载、动态 `Assembly.Load`、模板执行。
- 命令执行：`Process.Start`、`Runtime.exec`、`ProcessBuilder`、`child_process`、`os.system`、`subprocess`、shell 拼接、压缩/转换/Office/图片处理外部命令。

## 覆盖维度

| 维度 | 覆盖内容 |
|------|----------|
| D1 注入 | SQL 注入、命令注入、LDAP 注入、SSTI、SpEL、JNDI、模板注入 |
| D4 反序列化 | Java/Python/PHP 不安全反序列化 |
| D5 文件操作 | 上传/下载/路径遍历/任意读写 |
| D6 SSRF | URL 注入、协议限制、内网探测 |
| D7 加密与凭据 | 硬编码密钥/凭据、弱加密算法（仅可直接利用的） |
| D10 供应链 | 依赖中已知高危 CVE |

## 上下文保护规则（必须遵守）

1. **精准读取**：超过 500 行的文件不要整文件 Read。先用 Grep 定位 Sink，再用 Read 的 offset/limit 只读前后 50-100 行。
2. **调用链追踪器**：跨 2 个以上文件的数据流追踪，必须将每一跳写入 `audit/phase2/callchain_tracker.md` 再跳转到下一个文件，防止上下文丢失。格式：

```
## cc-001: [Sink 类型]
1. 入口: UserController.java:45 — 参数 userId 来自 @RequestParam
2. 中转: UserService.java:102 — 传入 findUser() 的 id 参数
3. Sink: UserDao.java:33 — 拼接进 SQL 字符串
状态: 已确认
```

## FSM 审计循环（每个 Sink 线索必须经过完整状态机）

对每个 sink 线索，执行以下状态机循环。禁止跳过任何状态，禁止在未达到终态的情况下进入下一条线索。

```
┌─────────┐    搜索结果非空     ┌─────────┐    代码上下文已读取    ┌─────────┐
│ SEARCH  │───────────────────>│ LOCATE  │──────────────────────>│  TRACE  │
│ 搜索定位 │<──── 需扩展搜索 ───│ 精确定位 │                       │ 数据流追踪│
└─────────┘                    └─────────┘                       └────┬────┘
                                                                      │
                                                          追踪完成/防护已识别
                                                                      │
┌─────────┐    结论明确         ┌──────────┐                          │
│ RECORD  │<───────────────────│ EVALUATE │<─────────────────────────┘
│ 记录结论 │    已确认/排除/阻塞 │ 成立性评估│──── 需要更多证据 ──> 返回 TRACE
└─────────┘                    └──────────┘
```

### 状态定义

| 状态 | 动作 | 完成条件 | 失败回退 |
|------|------|---------|----------|
| **SEARCH** | 用 Grep/rg 在批次文件中搜索 sink 模式 | 获得文件:行号命中列表 | 无命中 → 记录"本批次无此域 sink"→ RECORD |
| **LOCATE** | Read 命中位置前后 50-100 行，确认是真实 sink（非注释/测试/死代码） | 确认 sink 存在且有外部可达可能 | 假阳性 → 记录排除理由 → RECORD |
| **TRACE** | 从 sink 参数逆向追踪到入口（HTTP/RPC/MQ/文件导入），每跳写入 callchain_tracker.md | source-to-sink 链完整 | 链断裂 → 标记阻塞项 → EVALUATE |
| **EVALUATE** | 判断：(1)source 是否外部可控 (2)中途防护是否有效 (3)sink 是否可利用 | 得出"候选漏洞/排除/阻塞"结论 | 证据不足 → 返回 TRACE 补充 |
| **RECORD** | 写入 findings_batch/排除证据/阻塞项 | 状态机终态 | — |

### 循环规则

1. **严禁跳过 TRACE**：不得仅凭 SEARCH 结果直接进入 EVALUATE。
2. **EVALUATE 可回退**：评估时发现证据不足，必须返回 TRACE 补充（最多 3 次回退）。
3. **每条线索独立循环**：不得将多条 sink 线索合并为一次评估。
4. **进度可观测**：每完成一条线索的 RECORD，更新当前批次进度。

---

## 审计步骤

### 1. 定位 sink 上下文

- 先用 `rg` 定位符号，再读取相关代码上下文。
- 不得仅凭搜索结果报 finding，必须 Read 确认上下文。
- T1 文件完整 Read；T2/T3 先筛后读。
- 禁止只保留前 N 条搜索结果后继续推进。搜索结果过多时，按文件或模块分页处理，直到每条 sink 线索都有状态。

### 2. 逆向追踪 source-to-sink

从 sink 参数向上追踪到入口：

- HTTP/RPC/MQ/CLI/Job 参数。
- 数据库/缓存/MQ 的二次污染来源。
- 文件导入、上传文件内容、第三方回调内容。
- 配置项或环境变量是否可被低权限用户影响。

优先使用 LSP（goToDefinition、findReferences）；LSP 不可用时用 Grep + Read 逐跳验证。

跨两个以上文件的调用链必须写入 `audit/phase2/callchain_tracker.md`。

### 3. 重点关注的高级攻击向量

- **二次注入**：输入安全入库，但后续查出后拼接进另一个 SQL/命令
- **SSRF 绕过**：URL 可控 + 未校验内网 IP/重定向/DNS 重绑定
- **反序列化链**：Fastjson/Jackson/pickle/yaml + 不安全配置 + 可利用 Gadget
- **模板注入（SSTI）**：用户输入控制模板内容（非模板变量）
- **路径遍历**：filepath.Join/Path.resolve + 用户输入未 Clean
- **表达式注入**：导出/报表接口中 SpEL/OGNL/formula 等表达式字段用户可控
- **原型污染**（Node.js）：深合并/Object.assign 未阻止 `__proto__`

### 4. 防护点判断

记录并验证：

- 参数化查询、白名单、schema validation、路径规范化。
- URL 协议/IP/重定向/DNS rebinding 防护。
- 反序列化 safe mode、类型白名单、classpath gadget。
- Secret 是否为示例值、是否被生产 profile 加载、是否可用于签名/登录/连接。
- 模板 sandbox、表达式白名单。
- 文件类型、MIME、扩展名、解压路径、对象存储 key 约束。

防护是否有效留给阶段 4 最终验证，但阶段 2 必须记录线索。

### 5. 候选 finding 输出

每条候选必须包含：

- finding id。
- sink 类型、文件:行号、代码证据。
- source 入口、参数名、访问权限。
- source-to-sink 调用链（每跳标注文件:行号）。
- 已观察到的防护点和疑似缺失点。
- 疑似 CWE、OWASP Top 10、ASVS/WSTG。
- 当前验证等级：V0 或 V1。
- 阶段 4 需要验证的条件。

建议同步写入 `audit/phase2/candidate_findings.json`，schema 参考 `shared/whitebox_audit_schema.md`。

### 5.1 Top 10 适用域负证据要求

即使没有发现漏洞，也必须为存在明确线索的 OWASP Top 10 适用域留下可复算的排除证据。优先写入当前批次的 `findings_batch{N}.md`；阶段 3 汇总到 `false_positive_notes.md`。

排除证据必须包含：

- 审计对象总数、已处理数、未处理数。
- 每个 sink/入口/配置/依赖线索的文件:行号、source、sink 或控制点、防护点、结论。
- 对被排除项的代码证据，例如参数化占位符、严格类型转换、白名单、路径规范化、扩展名/魔数校验、协议/IP 白名单、依赖版本不受影响证明。
- 若任何项未处理，必须记录阻塞项，并阻止阶段 4。

### 6. 降噪规则

以下情况不作为候选漏洞，但可在覆盖矩阵或误报说明中记录：

- 注释代码、测试代码、样例代码、不可达代码。
- 无外部可控 source 的内部常量或启动配置。
- 框架已强制参数化且没有 raw 拼接逃逸点。
- 文件路径完全由服务器端枚举或不可被用户影响。
- 仅 DoS、日志、header、cookie flag 等无直接权限或数据危害的问题。

但如果它们能与其他漏洞形成攻击链，应保留到阶段 5 分析。

## 原语记录（与 findings 并行）

发现能力片段但不构成独立漏洞时，按 `skills/audit-primitives/SKILL.md` 格式写入 `audit/phase2/primitives_batch{N}.md`（如受限文件写/受限命令执行/内网探测等能力片段）。

无原语时也须创建该文件并写入 `> 本批次未发现原语。`

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
- `audit/phase2/primitives_batch{N}.md`
