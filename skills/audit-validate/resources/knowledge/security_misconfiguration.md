# 安全配置错误成立条件（通用）

供 阶段 4 判断；**框架无关**，对应 **OWASP Top 10 A05:2021 Security Misconfiguration**。适用于任意语言、框架与部署环境。

---

## 发现条件

- 代码或配置中开启**调试/诊断接口**、**默认凭据**、**过宽的 CORS/头**、**错误信息泄露**、或**不必要的危险功能**。

---

## 成立条件（按类型）

### 1. 调试/管理接口暴露

- **现象**：生产环境开启 debug、trace、Actuator、phpinfo、Swagger UI（未鉴权）、/debug、/console、堆栈跟踪等。
- **判定**：若对外可访问且无强认证 → 信息泄露或进一步利用；依框架（Spring Boot Actuator、Django DEBUG、Laravel APP_DEBUG 等）检查。

### 2. 默认/弱凭据

- **现象**：默认账号密码未修改、弱密码、或默认 Token/API Key 仍在使用。
- **判定**：需 Read 配置/文档或环境；若存在默认 creds 且可访问管理功能，成立。

### 3. CORS / 安全头过宽

- **现象**：CORS 配置为 `*` 或允许任意 Origin；缺少 CSP、X-Frame-Options、HSTS 等。
- **判定**：CORS `*` 在含敏感操作或 Cookie 的场景下可放大 CSRF/跨域风险；结合 scope_policy，强交互 CSRF 默认不纳入，但可记入配置缺陷。

### 4. 错误信息泄露

- **现象**：生产环境返回详细堆栈、SQL 错误、路径、版本号等给前端。
- **判定**：可辅助攻击者；标 Low/Info 除非可直接利用（如 SQL 报错注入）。

### 5. 不必要的危险功能

- **现象**：开启不必要的 HTTP 方法、目录列表、未禁用的默认管理员、或遗留测试接口。
- **判定**：依实际暴露与利用面；可标 Info 并建议关闭。

---

## 如何确认

- **Read 配置/环境**：application.properties、.env、config/*、Dockerfile、k8s ConfigMap 等；搜索 debug、password、secret、cors、origin。
- **多框架**：Spring Boot、Django、Laravel、Express、ASP.NET Core 等各有配置项；按实际技术栈查阅“生产安全配置”最佳实践。
- **报告约定**：注明配置来源（文件:行号或环境）；若仅开发环境存在则可不纳入或标 Info。

---

## 与“真实危害”范围

- 可直接导致未授权访问、信息泄露或 RCE（如 Actuator heapdump）→ 在默认 scope 内。
- 仅信息泄露或加固建议 → 可标 Low/Info。
