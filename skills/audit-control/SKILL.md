---
name: audit-control
description: 阶段 2 Control-driven 审计。从端点和业务能力检查认证/授权/资源归属/多租户隔离/状态机/敏感操作的控制缺失，发现未授权访问、越权（水平/垂直）、认证绕过、Token 伪造等漏洞，并发射原语片段。不负责数据流漏洞（→ audit-sink，并行执行）、不负责漏洞验证（→ audit-validate）。当 audit-orchestrator 进入 Phase 2 Control-driven 轨道时触发。
---

# 阶段 2 Control-driven 审计

## Banned Patterns（零容忍）

- 禁止：把死代码、日志输出过长、单纯的配置文件引用当漏洞 → 不分配编号。
- 禁止：报告"纵深防御缺失"类问题（如多一层校验更好）→ 不报。
- 禁止：因"看起来像测试接口"或"AI 自己认为利用门槛高"而跳过 P0/P1 高危端点。
- 禁止：仅模板下载/静态结构/公开字典等无敏感数据接口当未授权漏洞报。
- 禁止：未确认全局拦截器是否真正覆盖目标路径前就报"未授权"。
- 禁止：在本 skill 内执行漏洞验证（属于 `audit-validate` 职责）或记录数据流类漏洞（属于 `audit-sink` 职责）。

## 角色

阶段 2 的 Control-driven 轨道：从入口、权限模型和业务能力出发，发现"该有的安全控制缺失"。重点覆盖认证绕过、未授权访问、越权、IDOR/BOLA、多租户隔离、敏感信息泄露接口、多接口组合利用、业务逻辑漏洞。漏洞形态是"缺失"而非"某行代码错误"。**只报告能造成实际危害的缺失**。

## 输入

- `audit/phase0/config.json`（获取 mode 参数）
- `audit/phase1/endpoint_list.md`
- `audit/phase1/auth_model.md`
- `audit/phase1/framework_authz_map.md`
- `audit/phase1/secret_inventory.md`
- `audit/phase1/project_inventory.json`
- `audit/phase1/coverage_matrix.md`
- `audit/phase1/in_scope_files.txt`

## 模式行为差异

读取 `audit/phase0/config.json` 中的 `mode` 字段。两种模式的唯一区别在于**是否审计纯业务逻辑漏洞**。

### mode = "redteam"

审计所有**突破安全控制**的漏洞，跳过纯业务逻辑缺陷：

**完整执行**（安全控制类）：
- D2 认证：登录绕过、JWT 伪造/签名不校验、Session 固定、弱口令/默认凭证、验证码绕过、密码重置缺陷、SSO/OAuth 配置错误
- D3 授权（安全控制层面）：未授权访问高危接口、垂直越权、水平越权导致大规模数据泄露、IDOR/BOLA 突破权限边界
- D8 配置：Actuator/调试端点未授权、敏感信息泄露接口

**跳过**（纯业务逻辑缺陷 — 安全控制正常但业务规则有漏洞）：
- D9 中的业务逻辑部分：支付金额篡改、订单/审批状态机跳跃、优惠券/积分/库存规则绕过、竞态条件下的业务重复操作
- D3 中的业务级水平越权：查看他人地址/订单详情（未导致大规模数据泄露）
- Mass Assignment 修改业务字段（如修改自己订单的价格）

### mode = "full"

完整执行所有覆盖维度（D2-D9），包含 redteam 跳过的全部业务逻辑检查。

## 漏报红线（严禁遗漏高危未授权接口）

- 对所有高危功能接口（管理员添加、配置修改、敏感数据删除等）做**绝对地毯式扫描**。
- `LoginController` 中的 `/addAdmin` 等接口若无鉴权，必须作为严重/高危漏洞上报。
- 涉及增删改、敏感查询、高权限操作（`addAdmin / createUser / assignRole / delete`）的接口必须严格检查鉴权；即使有全局拦截器，也必须确认拦截器真正拦截了这些路径（路径匹配/前缀/大小写/通配符绕过）。

## 覆盖维度

| 维度 | 覆盖内容 |
|------|----------|
| D2 认证 | Token/Session/JWT/Filter 链/登录逻辑 |
| D3 授权 | CRUD 权限一致性、IDOR、水平/垂直越权 |
| D8 配置 | Actuator/调试端点未授权、敏感信息泄露 |
| D9 业务逻辑 | 竞态条件、Mass Assignment、越权操作 |

## 硬门禁：OWASP Top 10 控制面不得漏审

| Top 10 域 | Control-driven 必查线索 |
|-----------|--------------------------|
| A01 Broken Access Control | 未授权、越权、IDOR/BOLA、对象归属、租户隔离、批量操作、导出/下载/删除/配置接口 |
| A04 Insecure Design | 审批、支付、退款、库存、状态机、限流、幂等、业务前置条件缺失 |
| A05 Security Misconfiguration | 白名单、匿名路由、调试端点、错误回显、默认账号或默认开关 |
| A07 Identification and Authentication Failures | 登录、找回密码、验证码、会话、SSO/OAuth/OIDC、JWT、API key、Token 生命周期 |
| A09 Security Logging and Monitoring Failures | 认证失败、越权尝试、管理操作、敏感导出/删除/配置变更无审计，或日志泄露敏感数据 |

每个适用域必须有明确状态：

- 控制缺失或可绕过 → `candidate_findings.json`
- 控制存在且有代码证据 → 批次 findings 或阶段 3 反向审查中写明排除证据
- 缺少业务语义或运行配置上下文 → 阻塞项，**不得**宣称该 Top 10 域完成

## 审计步骤

### 1. 端点分级

- P0：无需认证或白名单端点（公开/回调）
- P1：普通用户/低权限可达端点
- P2：管理员或高权限端点
- P3：内部服务、回调、任务、MQ consumer、CLI

高价值关键词优先：`admin / role / permission / tenant / user / delete / update / export / download / payment / reset / callback / internal / debug / config / secret / credential / apikey / token / dump / log / backup`。

### 2. 框架级认证链验证

先按 `shared/framework_authz_checklist.md` 对项目框架检查，再对每个入口检查：

- 是否被全局 Filter/Interceptor/Middleware/Gateway 覆盖；遇到 `permitAll / @PermitAll / AllowAnonymous` 必须回溯实际拦截链确认含义
- 白名单、匿名注解是否合理
- 路径匹配是否存在前缀、大小写、编码、尾斜杠、通配符绕过
- JWT/session/API key 是否校验签名、过期、绑定身份、绑定租户
- SSO/OAuth/OIDC 是否校验 state、nonce、redirect_uri、issuer、audience、email_verified
- 框架注解、权限表、菜单权限、租户过滤、数据权限对详情/导出/下载/批量操作是否同样生效

> 各鉴权框架的常见绕过线索见 `shared/framework_catalog.md`（按需读取）。

### 3. 授权与资源归属

对敏感操作逐项确认：

- 是否校验当前用户拥有目标资源
- 是否只校验"已登录"不校验资源归属
- 普通用户是否可传 `role / isAdmin / tenantId / ownerId / price / status` 等敏感字段（ORM Mass Assignment）
- 批量接口是否只校验部分 ID
- 多租户查询是否缺少 tenant filter
- 管理员接口是否仅靠前端隐藏

### 4. 高危操作检查清单（P0/P1 优先）

| 类别 | 识别关键词 | 必查项 |
|------|-----------|--------|
| 登录/认证 | login / signin / ssoLogin / oauth/token / auth / authenticate | 请求体是否进入反序列化？是否会话固定绕过？Token/会话是否与身份强绑定？ |
| 密码重置/找回 | reset / resetPassword / forgot / changePassword | 目标用户 ID 是否可由请求参数任意指定？是否校验当前用户权限？ |
| 批量删除/更新 | deleteList / batchDelete / batchUpdate | 是否逐条校验 ID 归属和权限？ |
| 高权限账户创建/角色分配 | admin / super / root / role / permission / grant / assign | 是否允许未认证/低权限调用？是否可直接赋高权限？ |
| 回调/Webhook | 支付回调/短信回执/第三方回调 | 是否校验签名/时间戳/nonce？ |
| URL 拉取/代理（SSRF 入口） | 参数含 url / uri / target / callback | 是否限制协议和内网 IP？|
| 通用未授权 | 所有业务端点 | 是否被统一拦截器覆盖？是否存在配置遗漏？ |

### 5. 业务逻辑与状态机

重点关注：支付、订单、审批、优惠券、积分、库存、退款；重放、重复提交、并发、TOCTOU；状态跳跃（未支付 → 已发货、未审批 → 已通过）；金额/数量/折扣/角色由客户端控制；回调签名/幂等/时间戳/nonce。

业务意图无法从代码判断时标 `needs-info`，并列入待验证条件。

### 6. 未授权和敏感信息泄露接口专项

对所有 P0/P1 入口额外检查：

- 无认证访问是否能读取用户、订单、支付、文件、配置、日志、备份、调试信息
- 低权限用户是否能访问管理员、其他租户、其他用户或内部接口
- 导出、下载、日志、错误回显、debug、actuator、swagger、druid、metrics、heapdump 是否泄露敏感信息
- 接口响应是否含密码、hash、salt、token、secret、access key、连接串、私钥、身份证/手机号/邮箱等 PII
- 泄露 ID/token/路径/配置是否能作为下一步接口的输入，形成组合利用链
- 对 `secret_inventory.md` 中可疑 secret 追踪是否存在对应接口或服务可利用路径

### 7. 候选 finding 输出

每条候选必须包含：

- finding id
- 入口、HTTP 方法/协议、handler 文件:行号
- 期望控制：认证、角色、资源归属、租户、状态机
- 实际控制：已发现的拦截器、注解、查询条件、校验函数
- 缺失或绕过路径
- 可影响资产和所需权限
- 疑似 CWE / OWASP / ASVS / WSTG
- 当前验证等级 V0 / V1
- 阶段 4 需要验证的账号、业务数据或环境条件
- 未授权/越权/泄露类必须记录对照请求设计：无认证/低权限请求 vs 合法高权限请求 vs 预期安全行为 vs 实际突破点

### 7.1 Top 10 控制面适用域负证据要求

同 `audit-sink` 节 5.1 的负证据规则：未处理项必须列为阻塞项并阻止阶段 4。

## 防误报检查

不得把以下内容直接作为漏洞：

- 已有不可绕过的全局鉴权覆盖
- 当前用户确实有业务权限访问的数据
- 只有管理员可执行且符合业务设计的高危操作
- 仅模板下载、静态结构、公开字典等无敏感数据接口
- 测试接口未被生产路由加载

但若白名单/路径匹配/租户隔离/资源归属存在绕过线索，必须作为候选进入阶段 4。

## 与 Sink-driven 的关系

- Sink-driven 证明危险数据流。
- Control-driven 证明控制缺失。
- 同一漏洞可能需要两条证据链（如未授权文件下载既要证明入口无鉴权，也要证明文件路径或对象 ID 可控）。

## 原语记录（与 findings 并行）

按 `skills/audit-primitives/SKILL.md` 格式写入 `audit/phase2/primitives_batch{N}.md`（如 authn_bypass / authz_bypass / token_forgery / open_redirect 等）。无原语时也须创建该文件并写 `> 本批次未发现原语。`

## 进度要求

- 追加已审路径到 `audit/phase2/reviewed_paths_batch{N}.txt`
- 更新候选 findings
- 汇报精确覆盖：`已审 X / 应审 Y = Z%`
- 若 OWASP Top 10 控制面适用域线索存在，按域汇报 `processed/total/pending`；`pending > 0` 时**不得**进入阶段 4

## 输出

- `audit/phase2/findings_batch{N}.md`
- `audit/phase2/reviewed_paths_batch{N}.txt`
- `audit/phase2/candidate_findings.json`
- `audit/phase2/primitives_batch{N}.md`
