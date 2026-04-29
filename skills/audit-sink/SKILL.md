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

## 输出

- `audit/phase2/findings_batch{N}.md`
- `audit/phase2/reviewed_paths_batch{N}.txt`
- `audit/phase2/candidate_findings.json`
- `audit/phase2/callchain_tracker.md`
