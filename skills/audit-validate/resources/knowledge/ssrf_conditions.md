---
last_updated: "2026-04-30"
version: "1.0"
---

# SSRF 成立条件（通用）

供 阶段 4 判断；**框架无关**，对应 **OWASP Top 10 A10:2021 Server-Side Request Forgery**。适用于任意语言与 Web 框架。

---

## 发现条件

- 代码中**根据用户可控输入发起 HTTP/HTTPS 或其他协议的网络请求**（URL、host、path、scheme 等可由前端或参数传入）。

---

## 成立条件（按可控程度与协议）

- **URL 完全可控**：用户输入直接作为请求 URL（或仅做简单拼接）→ 可访问内网、云元数据、file://、dict:// 等则成立。
- **Host/Path 可控**：用户可指定 host 或 path，服务端拼接成完整 URL → 需检查是否限制协议（仅 http(s)）、是否限制目标 IP/域名（内网、回环、元数据地址）；未限制则成立。
- **协议限制**：若仅允许 https 且禁止内网段，则风险降低；若允许 file://、gopher://、dict:// 或未校验目标 IP，则高危。
- **云元数据**：若部署于云（AWS/GCP/Azure/阿里云等），可访问 169.254.169.254 或等价元数据地址 → 成立则可读敏感元数据。

---

## 如何确认

- **Read 代码**：定位发起请求的 API（HttpClient、fetch、requests.get、curl、file_get_contents、HttpRequest 等），追踪 URL/host 参数来源。
- **多语言示例**：Java HttpClient/URLConnection、Node axios/fetch、Python requests/urllib、PHP file_get_contents/curl、Go net/http、.NET HttpClient。
- **报告约定**：注明是否限制协议与目标；若无法确认是否被网关/策略拦截，标 **待验证（HYPOTHESIS）**。

---

## 与“真实危害”范围

- 可访问内网、云元数据、或可被用于端口扫描/代理 → 在默认 scope 内。
- 仅能请求公网且无敏感信息泄露路径 → 可标 Low 或 Info。
