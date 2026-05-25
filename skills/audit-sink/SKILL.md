---
name: audit-sink
description: 阶段 2 Sink-driven 数据流审计。从危险 API 向上追踪外部输入数据流，发现 RCE/SQL 注入/反序列化/SSRF/任意文件读写等候选漏洞，并发射原语片段。不负责认证/授权缺失类漏洞（→ audit-control，并行执行）、不负责漏洞验证（→ audit-validate）。当 audit-orchestrator 进入 Phase 2 Sink-driven 轨道时触发。
---

# 阶段 2 Sink-driven 审计

## Banned Patterns（零容忍）

- 禁止：把"整文件注释的死代码"、"无外部入口的配置/环境变量读取"、"日志输出格式"当作漏洞 → 直接丢弃，不分配编号。
- 禁止：仅 DoS、CSRF 防护缺失、SSRF 访问正常内网 Web 服务而无进一步利用、Cookie Secure 标记缺失、CORS 配置等"无实际危害项"→ 不分配编号。
- 禁止：因方法调用链较深就中途放弃数据流追踪。
- 禁止：主观臆断某些入口"不会被恶意用户调用"而跳过。
- 禁止：仅凭 `rg` 搜索结果直接报 finding；必须 Read 确认上下文。
- 禁止：搜索结果命中上万条后只挑前 N 条写报告 → 必须分批处理，每条 sink 线索都要有状态。
- 禁止：在本 skill 内执行漏洞验证（属于 `audit-validate` 职责）或记录 Control 类缺失（属于 `audit-control` 职责）。

## 角色

阶段 2 的 Sink-driven 轨道：从危险能力向上追踪输入来源，判断外部可控数据是否可达 sink、中途防护是否有效。**只记录有实际攻击路径的发现**，丢弃纯理论风险。此阶段输出**候选** finding，不做最终定性。

## 输入

- `audit/phase1/sink_list.md`
- `audit/phase1/endpoint_list.md`
- `audit/phase1/dependency_list.json`
- `audit/phase1/project_inventory.json`
- `audit/phase1/auth_model.md`
- `audit/phase1/in_scope_files.txt`

## 漏报红线（与降噪并存 — 严禁丢弃真实数据流漏洞）

- 必须完整追踪数据流；公网/内部可达端点能将污染数据传入 Sink 且未过滤 = 必报候选。
- 任何文件操作（上传/读取/写入）、执行层（SQL、命令执行、反序列化等）发现可疑数据流必须记录。

## 必审 sink 域

| 域 | 说明 |
|----|------|
| 命令执行 | 任何外部进程拉起 + 用户拼接 |
| 动态代码 | eval/动态编译/脚本引擎/动态 import |
| 反序列化 | Java/Python/PHP/.NET 各类不安全反序列化 + 缓存/MQ 二次反序列化 |
| 注入 | raw SQL/HQL/NoSQL/LDAP/XPath、字符串拼接查询、动态排序/字段名 |
| SSRF | URL fetch、代理、webhook callback、图片/文档转换、HTTP client |
| 文件 | 上传/下载/读取/写入/解压/路径拼接/对象存储 key |
| 模板/表达式 | SSTI、SpEL、OGNL、Velocity、FreeMarker、Handlebars、公式注入 |
| 加密/密钥/Secret | 硬编码凭据、JWT secret、API key、云密钥、弱随机、证书校验绕过 |

> 各语言典型 sink API 见 `shared/sink_catalog_by_lang.md`（按需读取，遇到陌生 API/语言时查）。

## 硬门禁：OWASP Top 10 适用域不得漏审

本轨道负责 sink 相关域，与 Control-driven 轨道共同覆盖完整 Top 10：

| Top 10 域 | Sink-driven 必查线索 |
|-----------|----------------------|
| A02 Cryptographic Failures | 弱哈希、弱随机、明文敏感数据、密钥/Token/连接串、证书校验关闭 |
| A03 Injection | SQL/ORM/NoSQL/LDAP/XPath/命令/模板/表达式注入、动态代码执行、动态排序/筛选/批量 ID |
| A05 Security Misconfiguration | 调试/错误回显、目录暴露、危险中间件开关 |
| A06 Vulnerable and Outdated Components | 依赖版本、已知 CVE、危险组件默认配置、反序列化 gadget |
| A08 Software and Data Integrity Failures | 文件上传与解析链、不安全反序列化、模板/插件/脚本更新、解压与导入链 |
| A10 SSRF | URL fetch、代理、webhook、回调、协议/IP/重定向控制 |

每条高风险线索必须形成明确结论：

- 外部输入可达 + 防护不足 → 进入 `candidate_findings.json`
- 已确认参数化/白名单/类型强约束/路径规范化/版本不受影响 → 在批次 findings 或阶段 3 反向审查中写明排除证据（**Top 10 负证据要求**）
- 上下文不足 → 写入阻塞项，**不得**宣称该 Top 10 域完成

### RCE / 反序列化显式门禁

反序列化、动态代码执行、命令执行是高危 sink，不得因为已覆盖 A03/A08 就省略逐项审计。必须枚举并逐项处理（API 清单见 `shared/sink_catalog_by_lang.md`）。

## 上下文保护规则

1. **精准读取**：>500 行文件不要整文件 Read。先 `rg` 定位 Sink，再 Read `offset/limit` 只读前后 50-100 行。
2. **调用链追踪器**：跨 2 个以上文件的数据流必须将每一跳写入 `audit/phase2/callchain_tracker.md`。格式简洁实用：

```
## cc-001: [Sink 类型]
可达性：sink可达 ✓ | source可控 ✓ | 防护缺失 ✓
调用链：
  UserController.java:45  — @RequestParam String userId（外部输入）
  → UserService.java:102  — findUser(id) 参数传递
  → UserDao.java:33       — Statement.executeQuery("...WHERE id=" + id)（sink）
防护分析：UserDao.java:31 有 regex 校验但 FALSE 分支绕过
判定：候选成立（绕过点：输入非数字字符走 FALSE 分支）
```

注意事项：
- base64/urlencode 等编码变换**不是**清污操作
- if/switch 分支需检查每个分支的污点状态
- 遇到可疑 sanitizer 时按 `shared/taint_propagation.md` 四问判别真伪

## 审计步骤

### 1. 定位 sink 上下文

- `rg` 定位符号 → Read 确认上下文。
- T1 文件完整 Read；T2/T3 先筛后读。
- 搜索结果过多 → 按文件/模块分页处理，**每条 sink 线索都要有状态**（已确认/已排除/阻塞）。

### 2. 逆向追踪 source-to-sink

从 sink 参数向上追到入口：

- HTTP / RPC / MQ / CLI / Job 参数
- 数据库 / 缓存 / MQ 的二次污染来源
- 文件导入、上传文件内容、第三方回调内容
- 配置项或环境变量是否可被低权限用户影响

优先用 LSP（goToDefinition / findReferences），不可用时用 Grep + Read 逐跳验证。跨两个以上文件的调用链必须写 `callchain_tracker.md`。

### 3. 重点关注的高级攻击向量

- 二次注入：输入安全入库，但查出后拼进另一个 SQL/命令
- SSRF 绕过：URL 可控 + 未校验内网 IP / 重定向 / DNS 重绑定
- 反序列化链：Fastjson/Jackson/pickle/yaml + 不安全配置 + 可利用 Gadget
- 模板注入（SSTI）：用户输入控制**模板内容**（非模板变量）
- 路径遍历：`filepath.Join / Path.resolve` + 用户输入未 Clean
- 表达式注入：导出/报表接口中 SpEL/OGNL/formula 等表达式字段用户可控
- 原型污染（Node.js）：深合并 / `Object.assign` 未阻止 `__proto__`

### 4. 防护点判断 + 可达性验证

记录并验证：参数化查询、白名单、schema validation、路径规范化、URL 协议/IP/重定向/DNS rebinding 防护、反序列化 safe mode、类型白名单、模板 sandbox、表达式白名单、文件类型 MIME/扩展名/解压路径/对象存储 key 约束。

**可达性验证（三级分层，替代原 R1-R7 全步骤）：**

| 级别 | 条件 | 验证方式 | 结论 |
|------|------|----------|------|
| 简单（≤2 跳） | 入口直接调用 sink | Read 确认即可 | 直接判定 |
| 中等（3-4 跳） | 经过 service/dao 层 | 逐跳 Read + Grep 确认每一步传递 | 记录调用链 |
| 复杂（>4 跳） | 跨多模块/多文件/异步 | 记录已确认的前 N 跳 + 标注断点 | 标 V1 待验证 |

**核心检查项**（每条候选至少确认以下 3 点）：
1. **sink 可达**：sink 代码被生产路径实际调用（非死代码/非测试）
2. **source 可控**：外部输入能影响 sink 参数（标注污点传递路径）
3. **防护缺失/可绕过**：中间无有效过滤，或过滤可绕过

不通过 → 排除（写负证据）；部分不确定 → 标待验证（不丢弃）。

### 4.1 遇到本表外 sink → 联网

`shared/sink_catalog_by_lang.md` 覆盖主流；遇到陌生/小众/新 CVE 涌现的 sink，必须按 `shared/external_knowledge_protocol.md` §2 表 #1/#6 主动联网查官方语义 + 公开 CVE。每条联网引用必须按 §4 格式留 URL 写入 finding 的「外部依据」字段。**禁止编造 sink 危险性。**

### 5. 候选 finding 输出

每条候选必须包含：

- finding id
- sink 类型、文件:行号、代码证据
- source 入口、参数名、访问权限
- source-to-sink 调用链（每跳标注文件:行号）
- 已观察到的防护点和疑似缺失点
- 疑似 CWE、OWASP Top 10、ASVS/WSTG
- 当前验证等级：V0 或 V1
- 阶段 4 需要验证的条件

同步写入 `audit/phase2/candidate_findings.json`（schema 见 `shared/whitebox_audit_schema.md`）。

### 5.1 Top 10 适用域负证据要求

存在明确线索但无候选 finding 的 OWASP Top 10 适用域，必须留可复算的排除证据：审计对象总数、已处理数、未处理数；每个 sink/入口/配置/依赖线索的 `file:line`、source、sink/控制点、防护点、结论；代码证据（参数化占位符、严格类型转换、白名单、路径规范化、扩展名/魔数校验、协议/IP 白名单、依赖版本不受影响证明）。任何未处理项 → 阻塞项 → 阻止阶段 4。

### 6. 降噪规则（与 Banned Patterns 一致）

以下不作为候选漏洞（可在覆盖矩阵或误报说明中记录）：

- 注释代码、测试代码、样例代码、不可达代码
- 无外部可控 source 的内部常量或启动配置
- 框架已强制参数化且无 raw 拼接逃逸点
- 文件路径完全由服务器端枚举或不可被用户影响
- 仅 DoS、日志、header、cookie flag 等无直接权限或数据危害的问题

但如果能与其他漏洞形成攻击链，应保留到阶段 5 分析（写入原语）。

## 原语记录（与 findings 并行）

发现能力片段但不构成独立漏洞时，按 `skills/audit-primitives/SKILL.md` 格式写入 `audit/phase2/primitives_batch{N}.md`（如受限文件写 / 受限命令执行 / 内网探测等）。无原语时也须创建该文件并写 `> 本批次未发现原语。`

## 进度要求

每批审计后：

- 追加已审路径到 `audit/phase2/reviewed_paths_batch{N}.txt`
- 更新候选 findings
- 汇报精确覆盖：`已审 X / 应审 Y = Z%`
- 若 OWASP Top 10 适用域线索存在，按域汇报 `processed/total/pending`；`pending > 0` 时**不得**进入阶段 4

## 输出

- `audit/phase2/findings_batch{N}.md`
- `audit/phase2/reviewed_paths_batch{N}.txt`
- `audit/phase2/candidate_findings.json`
- `audit/phase2/callchain_tracker.md`
- `audit/phase2/primitives_batch{N}.md`
