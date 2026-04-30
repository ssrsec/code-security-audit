---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- 认证缺陷
- authentication failure
- 会话管理
- 登录绕过
- 密码重置
- 暴力破解
- JWT
- Session
- Cookie
- OAuth
- OIDC
- SSO
cwe:
- CWE-287
- CWE-384
- CWE-613
owasp:
- A07:2021
nuclei_tags:
- auth-bypass
- default-login
frameworks:
- Java
- Python
- PHP
- Node.js
- Go
- .NET
vuln_types:
- authentication
- session
- auth_bypass
severity_range:
- medium
- critical
references:
- OWASP Top 10 A07:2021
- OWASP CheatSheetSeries/Authentication
---


# 认证与身份验证缺陷成立条件（通用）

供阶段 4 判断；**框架无关**，对应 **OWASP Top 10 A07:2021 Identification and Authentication Failures**。与授权（authorization_model.md）互补：认证解决"是谁"，授权解决"能做什么"。

---

## 发现条件

- 代码或配置中涉及**登录、会话、密码策略、多因素认证、忘记密码、账户锁定**等；或存在**会话固定、凭证泄露、默认账号**等风险。

---

## 成立条件（按类型）

### 1. 会话/Token 缺陷

- **现象**：登录后 Session ID 不变（会话固定）；Token 存于 localStorage 且无 HttpOnly；Token 过期时间过长或可续期无限制。
- **判定**：会话固定可导致劫持；Token 存储与过期策略依最佳实践判断。

### 2. 密码策略与存储

- **现象**：无复杂度要求、无锁定策略、密码以弱哈希或明文存储（见 cryptographic_failures.md）。
- **判定**：弱策略+弱存储 → 成立；仅弱策略可标 Low/Info。

### 3. 忘记密码/重置密码

- **现象**：重置链接可预测、无过期、或可指定任意用户（见 audit-control 的 P0：密码重置无权限校验）。
- **判定**：可接管任意账户 → 在默认 scope 内，High。

### 4. 默认/测试账号

- **现象**：存在未删除的默认管理员、测试账号、或硬编码密码。
- **判定**：若可登录且权限高，成立。

### 5. 多因素认证缺失

- **现象**：敏感操作（支付、改密、改邮箱）仅依赖单因素。
- **判定**：依业务与策略要求；可标建议项（Low/Info）除非合规强制。

### 6. 登录响应替换 / 会话绑定缺失（必审，严禁漏报）

- **现象**：登录接口仅校验请求体中的用户名/密码（或 token），但**未将登录成功结果与当前请求/会话强绑定**；攻击者可将**他人登录成功后的完整 HTTP 响应包**复制，在自身请求的响应中替换返回，从而以他人身份登录（含管理员）。
- **典型场景**：前端或网关仅根据「响应体含 token/成功码」即认为登录成功，不校验该响应是否来自当前请求对应的服务端生成；或服务端未将 session/token 与请求来源/会话 ID 绑定。
- **判定**：若存在「复制他人登录成功响应 → 替换到当前请求 → 以该用户身份通过鉴权」的可复现路径，则成立；**严重程度**：可登录管理员则为严重，可登录任意普通用户则为高。
- **验证**：Read 登录接口实现与前端/网关对「登录成功」的判定逻辑；确认是否存在「响应替换即可登录」的缺失校验。

---

## 与授权、CSRF 的区分

- **授权**：见 authorization_model.md（谁有权访问哪条 URL/资源）。
- **CSRF**：需用户交互（点击恶意链接等）；按 audit_discipline 默认不纳入"真实危害"，除非例外（如一次点击即高价值操作）。

---

## 如何确认

- **Read 代码/配置**：登录逻辑、Session/Token 生成与校验、密码重置流程、账户锁定与重试。
- **多语言/框架**：各框架的 auth 中间件、session 存储、password hashing；与 cryptographic_failures、authorization_model 联合使用。
- **报告约定**：注明认证方式与缺陷类型；若依赖部署（如是否启用 MFA），可标 **V1 待验证（HYPOTHESIS）**，并说明需要验证的部署条件。
