---
name: audit-control
description: 阶段 2 Control-driven 审计。从端点和业务能力检查认证、授权、资源归属、多租户隔离、状态机和敏感操作控制缺失。由 audit-orchestrator 在 Phase 2 与 audit-sink 并行调度，发现未授权访问、越权（水平/垂直）、认证绕过、Token 伪造等漏洞。**同时输出 primitives_batch{N}.md 原语批次文件**（记录 authn_bypass/authz_bypass/token_forgery/open_redirect 等能力片段供组合推理）。
---

# Control-driven 审计（阶段 2）

## 角色

负责阶段 2 的 Control-driven 轨道：从入口、权限模型和业务能力出发，发现"该有的安全控制缺失"。此轨道重点覆盖认证绕过、未授权访问、越权、IDOR/BOLA、多租户隔离、敏感信息泄露接口、多接口组合利用和业务逻辑漏洞。漏洞形态是"缺失"而非"某行代码错误"。**只报告能造成实际危害的缺失**，不报告"纵深防御缺失"类问题。

## 输入

- `audit/phase1/endpoint_list.md`
- `audit/phase1/auth_model.md`
- `audit/phase1/framework_authz_map.md`
- `audit/phase1/secret_inventory.md`
- `audit/phase1/project_inventory.json`
- `audit/phase1/coverage_matrix.md`
- `audit/phase1/in_scope_files.txt`

## 漏报红线（严禁遗漏高危未授权接口）

- 必须对项目中所有高危功能接口（如管理员添加、配置修改、敏感数据删除等）进行**绝对地毯式扫描**。
- 例如 `LoginController` 中的 `/addAdmin` 此类接口，如果不做鉴权，必须作为严重/高危漏洞上报。
- 绝不能因为"看起来像个测试接口"或"AI 自己认为利用门槛高"而跳过。对于未授权直接创建高权限账户或直接窃取数据的接口，坚决作为漏洞报出。

## 降噪与防漏报原则

- **极致降噪：严禁报告无危害项**：死代码、日志输出过长、仅仅是配置文件引用等，只要没有导致实质性的越权或数据未授权访问，坚决不记录为发现。
- **防漏报核心**：任何涉及增删改、敏感查询、高权限操作（如 `addAdmin`、`createUser`、`assignRole`、`delete`）的接口，必须严格检查鉴权逻辑。即使项目存在全局拦截器，也必须确认该拦截器是否真正拦截了这些路径，或者是否存在绕过（如路径匹配不严）。
- 仅登录用户可访问的模板下载/静态结构接口（无敏感数据）不作为漏洞。

## 覆盖维度

本轨道负责以下安全维度：

| 维度 | 覆盖内容 |
|------|----------|
| D2 认证 | Token/Session/JWT/Filter 链/登录逻辑 |
| D3 授权 | CRUD 权限一致性、IDOR、水平/垂直越权 |
| D8 配置 | Actuator/调试端点未授权、敏感信息泄露 |
| D9 业务逻辑 | 竞态条件、Mass Assignment、越权操作 |

## 硬门禁：OWASP Top 10 控制面不得漏审

以下不是新增输出标准，而是阶段 2 的一致性约束：只要项目存在 OWASP Top 10 控制面线索，就必须形成候选 finding、批次排除证据或阻塞项。

| OWASP Top 10 域 | Control-driven 必查线索 |
|-----------------|--------------------------|
| A01 Broken Access Control | 未授权、越权、IDOR/BOLA、对象归属、租户隔离、批量操作、导出/下载/删除/配置接口 |
| A04 Insecure Design | 审批、支付、退款、库存、状态机、限流、幂等、业务前置条件缺失 |
| A05 Security Misconfiguration | 白名单、匿名路由、调试端点、错误回显、CSRF/CORS/Header、默认账号或默认开关 |
| A07 Identification and Authentication Failures | 登录、找回密码、验证码、会话、SSO/OAuth/OIDC、JWT、API key、Token 生命周期 |
| A09 Security Logging and Monitoring Failures | 认证失败、越权尝试、管理操作、敏感导出/删除/配置变更无审计，或日志泄露敏感数据 |

每个适用域必须有明确状态：
- 控制缺失或可绕过：进入 `candidate_findings.json`。
- 控制存在且有代码证据：在批次 findings 或阶段 3 反向审查中写明排除证据。
- 缺少业务语义或运行配置上下文：写入阻塞项，不得宣称该 Top 10 域完成。

## FSM 审计循环（每个端点/控制点必须经过完整状态机）

对每个端点或控制检查项，执行以下状态机循环。禁止跳过任何状态，禁止在未达到终态的情况下进入下一条检查。

```
┌─────────┐    端点已枚举       ┌─────────┐    拦截链已读取        ┌─────────┐
│ SEARCH  │───────────────────>│ LOCATE  │──────────────────────>│  TRACE  │
│ 枚举端点 │<──── 需扩展枚举 ───│ 精确定位 │                       │ 控制链追踪│
└─────────┘                    └─────────┘                       └────┬────┘
                                                                      │
                                                          追踪完成/控制已确认
                                                                      │
┌─────────┐    结论明确         ┌──────────┐                          │
│ RECORD  │<───────────────────│ EVALUATE │<─────────────────────────┘
│ 记录结论 │    缺失/有效/阻塞   │ 控制评估  │──── 需要更多证据 ──> 返回 TRACE
└─────────┘                    └──────────┘
```

### 状态定义

| 状态 | 动作 | 完成条件 | 失败回退 |
|------|------|---------|----------|
| **SEARCH** | 枚举端点并按风险分级（P0→P3） | 获得端点列表及优先级排序 | 无端点 → 记录"本批次无入口" → RECORD |
| **LOCATE** | Read handler 代码，识别拦截器/注解/中间件配置 | 确认该端点的认证/授权控制链 | 控制链不明确 → 扩展搜索 Filter/Interceptor |
| **TRACE** | 追踪完整鉴权链：Filter → Interceptor → 注解 → 方法内检查 → 数据查询条件 | 链完整，每环有文件:行号 | 链断裂 → 标记阻塞项 → EVALUATE |
| **EVALUATE** | 判断：(1)控制是否存在 (2)控制是否可绕过 (3)资源归属是否校验 | 得出"控制缺失/控制有效/阻塞"结论 | 证据不足 → 返回 TRACE 补充 |
| **RECORD** | 写入 findings_batch/排除证据/阻塞项 | 状态机终态 | — |

### 循环规则

1. **严禁跳过 TRACE**：不得仅凭端点列表和注解名称直接判定"有鉴权"。
2. **EVALUATE 可回退**：评估时发现拦截器配置有歧义，必须返回 TRACE 读取实际拦截逻辑（最多 3 次回退）。
3. **P0 端点必须逐个循环**：P0 高危端点不得批量评估。
4. **进度可观测**：每完成一个端点的 RECORD，更新当前批次进度。

---

## 审计步骤

### 1. 端点分级

按风险排序：

- P0：无需认证或白名单端点（白名单/公开接口/回调等）
- P1：普通用户/低权限可达端点（已认证低权限可达）
- P2：管理员或高权限端点
- P3：内部服务、回调、任务、MQ consumer、CLI

高价值关键词必须优先：`admin`、`role`、`permission`、`tenant`、`user`、`delete`、`update`、`export`、`download`、`payment`、`reset`、`callback`、`internal`、`debug`、`config`、`secret`、`credential`、`apikey`、`token`、`dump`、`log`、`backup`。

### 2. 框架级认证链验证

先按 `shared/framework_authz_checklist.md` 对项目实际框架检查，再对每个入口检查：

- 是否被全局 Filter/Interceptor/Middleware/Gateway 覆盖。遇到 `permitAll/@PermitAll/AllowAnonymous` 时，必须回溯实际拦截链确认真实含义。
- 白名单、匿名注解、permitAll/AllowAnonymous 是否合理。
- 路径匹配是否存在前缀、大小写、编码、尾斜杠、通配符绕过。
- JWT/session/API key 是否校验签名、过期、绑定身份、绑定租户。
- SSO/OAuth/OIDC 是否校验 state、nonce、redirect_uri、issuer、audience、email_verified。
- 框架注解、权限表、菜单权限、租户过滤、数据权限是否对详情、导出、下载、批量操作同样生效。

### 3. 授权与资源归属

对敏感操作逐项确认：

- 是否校验当前用户拥有目标资源。
- 是否存在只校验"已登录"但不校验资源归属。
- 是否存在普通用户可传 `role`、`isAdmin`、`tenantId`、`ownerId`、`price`、`status` 等敏感字段（ORM Mass Assignment 风险）。
- 是否存在批量接口只校验部分 ID。
- 是否存在多租户查询缺少 tenant filter。
- 是否存在管理员接口仅靠前端隐藏。

### 4. 高危操作检查清单（P0/P1 优先）

#### P0：登录/认证接口（必审）
- **识别**：login、signin、ssoLogin、oauth/token、auth、authenticate
- **检查**：请求体是否进入反序列化？是否存在会话固定绕过？Token/会话是否与身份强绑定？

#### P0：密码重置/找回
- **识别**：reset、resetPassword、forgot、changePassword
- **检查**：目标用户 ID 是否可由请求参数任意指定？是否校验当前用户权限？

#### P0：批量删除/更新
- **识别**：deleteList、batchDelete、batchUpdate
- **检查**：是否逐条校验 ID 归属和权限？

#### P0：高权限账户创建/角色分配
- **识别**：涉及 admin/super/root/role/permission/grant/assign 的接口
- **检查**：是否允许未认证/低权限调用？是否可直接赋高权限？

#### P0：回调/Webhook
- **识别**：支付回调、短信回执、第三方回调
- **检查**：是否校验签名/时间戳/nonce？

#### P0：URL 拉取/代理（SSRF）
- **识别**：参数含 url/uri/target/callback
- **检查**：是否限制协议和内网 IP？

#### P1：通用未授权访问
- **识别**：所有业务端点
- **检查**：是否被统一拦截器覆盖？是否存在配置遗漏？

### 5. 业务逻辑与状态机

重点关注：

- 支付、订单、审批、优惠券、积分、库存、退款。
- 重放、重复提交、并发、TOCTOU。
- 状态跳跃：未支付 → 已发货、未审批 → 已通过。
- 金额、数量、折扣、权限角色由客户端控制。
- 回调签名、幂等、时间戳、nonce。

业务意图无法从代码判断时标记 `needs-info`，并列入待验证条件。

### 6. 未授权和敏感信息泄露接口专项

对所有 P0/P1 入口额外检查：

- 无认证访问是否能读取用户、订单、支付、文件、配置、日志、备份、调试信息。
- 低权限用户是否能访问管理员、其他租户、其他用户或内部接口。
- 导出、下载、日志、错误回显、debug、actuator、swagger、druid、metrics、heapdump 是否泄露敏感信息。
- 接口响应中是否包含密码、hash、salt、token、secret、access key、连接串、私钥、身份证/手机号/邮箱等 PII。
- 泄露出的 ID、token、路径、配置是否能作为下一步接口的输入，形成组合利用链。
- 对 `secret_inventory.md` 中可疑 secret 追踪是否存在对应接口或服务可利用路径。

### 7. 候选 finding 输出

每条候选必须包含：

- finding id。
- 入口、HTTP 方法/协议、handler 文件:行号。
- 期望控制：认证、角色、资源归属、租户、状态机。
- 实际控制：已发现的拦截器、注解、查询条件、校验函数。
- 缺失或绕过路径。
- 可影响资产和所需权限。
- 疑似 CWE/OWASP/ASVS/WSTG。
- 当前验证等级 V0/V1。
- 阶段 4 需要验证的账号、业务数据或环境条件。
- 若是未授权/越权/泄露类 finding，必须记录对照请求设计：无认证/低权限请求、合法高权限请求、预期安全行为、实际突破点。

### 7.1 Top 10 适用域负证据要求

即使没有发现漏洞，也必须为存在明确线索的 OWASP Top 10 控制面适用域留下可复算的排除证据。优先写入当前批次的 `findings_batch{N}.md`；阶段 3 汇总到 `false_positive_notes.md`。

排除证据必须包含：
- 审计对象总数、已处理数、未处理数。
- 每个入口/业务能力/配置点的文件:行号、期望控制、实际控制、防护点、结论。
- 对被排除项的代码证据，例如全局鉴权链、角色/权限表、资源归属查询、租户过滤、状态机校验、OAuth/OIDC 校验、审计日志写入点。
- 若任何项未处理，必须记录阻塞项，并阻止阶段 4。

## 防误报检查

不得把以下内容直接作为漏洞：

- 已有不可绕过的全局鉴权覆盖。
- 当前用户确实有业务权限访问的数据。
- 只有管理员可执行且符合业务设计的高危操作。
- 仅模板下载、静态结构、公开字典等无敏感数据接口。
- 测试接口未被生产路由加载。

但如果白名单、路径匹配、租户隔离或资源归属存在绕过线索，必须作为候选进入阶段 4。

## 与 Sink-driven 的关系

- Sink-driven 证明危险数据流。
- Control-driven 证明控制缺失。
- 同一漏洞可能同时需要两条证据链，例如未授权文件下载既要证明入口无鉴权，也要证明文件路径或对象 ID 可控。

## 原语记录（与 findings 并行）

发现能力片段但不构成独立漏洞时，按 `skills/audit-primitives/SKILL.md` 格式写入 `audit/phase2/primitives_batch{N}.md`（如 authn_bypass/authz_bypass/token_forgery/open_redirect 等）。无原语时也须创建该文件并写入 `> 本批次未发现原语。`

## 进度要求

每批审计后：

- 追加已审路径到 `audit/phase2/reviewed_paths_batch{N}.txt`。
- 更新候选 findings。
- 汇报精确覆盖：`已审 X / 应审 Y = Z%`。
- 若 OWASP Top 10 控制面适用域线索存在，按域汇报 `processed/total/pending`；pending 大于 0 时不得进入阶段 4。

## 输出

- `audit/phase2/findings_batch{N}.md`
- `audit/phase2/reviewed_paths_batch{N}.txt`
- `audit/phase2/candidate_findings.json`
- `audit/phase2/primitives_batch{N}.md`
