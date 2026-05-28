# Live Target Protocol

## 目标

靶场验证用于在授权环境中证明漏洞可利用性。生产协议默认允许 L1 和 L2 自动执行，禁止 L3，且不脱敏内部证据。

## 等级

### L1：只读验证

允许：

- 只读 SQL。
- 无状态 HTTP 请求。
- 文件读取。
- SSRF 到授权 mock/OAST。
- 认证/越权对照读取。

要求：

- request。
- response。
- assertion。
- environment fingerprint。

### L2：可回滚写操作

L2 不需要每条单独询问工程师。只要目标靶场、测试账号和审计范围已经授权，AI 可以自动执行 L2，但必须完整记录回滚证据。

允许：

- 插入临时数据。
- 更新测试配置。
- 写临时文件。
- 创建测试会话。
- 可回滚的权限/角色测试。

必须记录：

- baseline。
- mutation。
- proof。
- cleanup。
- post-cleanup assert。

若 cleanup 不可行：

- 必须记录 `cleanupUnavailableReason`。
- 必须进入 report limitations。
- 不得描述为“可清理”。

### L3：不可逆或高破坏操作

默认禁止。

L3 不是常规验证级别。只有当验证动作会造成不可逆、高破坏或明显超出测试靶场预期影响时，才需要工程师逐次授权。

包括：

- DROP / 大规模 DELETE。
- 改真实用户密码。
- 反弹 shell。
- 持久化 webshell。
- 横向移动。
- 真实业务破坏。

L3 必须有 explicit approval 记录。

## 靶场异常

### live target down

- 暂停 V4。
- 继续静态/本地验证。
- 标记 affected tasks。

### partial deploy

- 对可用入口继续验证。
- 对不可用入口标 `blocked_environment`。
- 不将 404 直接判为不成立。

### suspected pollution

- 查询 mutation history。
- 暂停高风险 L2。
- 输出环境影响说明。

## 证据完整性

内部权威证据包不脱敏，必须保留复现所需的 Cookie、Token、Hash、路径、响应摘要和业务 ID。

## 禁止

- L2 无 cleanup 记录。
- L3 无批准执行。
- 仅 HTTP 200 标已确认。
- 靶场缺部署就判白盒漏洞不成立。
- 用“同上”“上一步”替代 request/cookie/token 来源。
