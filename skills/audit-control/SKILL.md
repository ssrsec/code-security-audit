---
name: audit-control
description: 阶段 2 Control-driven 审计。从端点和业务能力检查认证、授权、资源归属、多租户隔离、状态机和敏感操作控制缺失。
---

# Control-driven 审计（阶段 2）

## 角色

负责阶段 2 的 Control-driven 轨道：从入口、权限模型和业务能力出发，发现“该有的安全控制缺失”。此轨道重点覆盖认证绕过、未授权访问、越权、IDOR/BOLA、多租户隔离、敏感信息泄露接口、多接口组合利用和业务逻辑漏洞。

## 输入

- `audit/phase1/endpoint_list.md`
- `audit/phase1/auth_model.md`
- `audit/phase1/framework_authz_map.md`
- `audit/phase1/secret_inventory.md`
- `audit/phase1/project_inventory.json`
- `audit/phase1/owasp_coverage_matrix.md`
- `audit/phase1/in_scope_files.txt`

## 覆盖维度

本轨道负责以下安全维度（参考 `shared/dimensions.md`）：

| 维度 | 覆盖内容 |
|------|----------|
| D2 认证 | Token/Session/JWT/Filter 链/登录逻辑 |
| D3 授权 | CRUD 权限一致性、IDOR、水平/垂直越权 |
| D8 配置 | Actuator/调试端点未授权、敏感信息泄露 |
| D9 业务逻辑 | 竞态条件、Mass Assignment、越权操作 |

## 审计步骤

### 1. 端点分级

按风险排序：

- P0：无需认证或白名单端点。
- P1：普通用户/低权限可达端点。
- P2：管理员或高权限端点。
- P3：内部服务、回调、任务、MQ consumer、CLI。

高价值关键词必须优先：`admin`、`role`、`permission`、`tenant`、`user`、`delete`、`update`、`export`、`download`、`payment`、`reset`、`callback`、`internal`、`debug`、`config`、`secret`、`credential`、`apikey`、`token`、`dump`、`log`、`backup`。

### 2. 框架级认证链验证

先按 `shared/framework_authz_checklist.md` 对项目实际框架检查，再对每个入口检查：

- 是否被全局 Filter/Interceptor/Middleware/Gateway 覆盖。
- 白名单、匿名注解、permitAll/AllowAnonymous 是否合理。
- 路径匹配是否存在前缀、大小写、编码、尾斜杠、通配符绕过。
- JWT/session/API key 是否校验签名、过期、绑定身份、绑定租户。
- SSO/OAuth/OIDC 是否校验 state、nonce、redirect_uri、issuer、audience、email_verified。
- 框架注解、权限表、菜单权限、租户过滤、数据权限是否对详情、导出、下载、批量操作同样生效。

### 3. 授权与资源归属

对敏感操作逐项确认：

- 是否校验当前用户拥有目标资源。
- 是否存在只校验“已登录”但不校验资源归属。
- 是否存在普通用户可传 `role`、`isAdmin`、`tenantId`、`ownerId`、`price`、`status` 等敏感字段。
- 是否存在批量接口只校验部分 ID。
- 是否存在多租户查询缺少 tenant filter。
- 是否存在管理员接口仅靠前端隐藏。

### 4. 业务逻辑与状态机

重点关注：

- 支付、订单、审批、优惠券、积分、库存、退款。
- 重放、重复提交、并发、TOCTOU。
- 状态跳跃：未支付 -> 已发货、未审批 -> 已通过。
- 金额、数量、折扣、权限角色由客户端控制。
- 回调签名、幂等、时间戳、nonce。

业务意图无法从代码判断时标记 `needs-info`，并列入待验证条件。

### 5. 未授权和敏感信息泄露接口专项

对所有 P0/P1 入口额外检查：

- 无认证访问是否能读取用户、订单、支付、文件、配置、日志、备份、调试信息。
- 低权限用户是否能访问管理员、其他租户、其他用户或内部接口。
- 导出、下载、日志、错误回显、debug、actuator、swagger、druid、metrics、heapdump 是否泄露敏感信息。
- 接口响应中是否包含密码、hash、salt、token、secret、access key、连接串、私钥、身份证/手机号/邮箱等 PII。
- 泄露出的 ID、token、路径、配置是否能作为下一步接口的输入，形成组合利用链。
- 对 `secret_inventory.md` 中可疑 secret 追踪是否存在对应接口或服务可利用路径。

### 6. 候选 finding 输出

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

## 输出

- `audit/phase2/findings_batch{N}.md`
- `audit/phase2/reviewed_paths_batch{N}.txt`
- `audit/phase2/candidate_findings.json`
