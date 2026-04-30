---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- SSTI
- 模板注入
- Server-Side Template Injection
- Velocity
- VelocityEngine
- evaluate
- FreeMarker
- Thymeleaf
- Handlebars
cwe:
- CWE-1336
- CWE-94
cwe_rank: 10
owasp:
- A03:2021
nuclei_tags:
- ssti
- template-injection
frameworks:
- Java
vuln_types:
- injection
- ssti
- rce
severity_range:
- high
- critical
references:
- 'CWE Top 25 #10 Code Injection (2025)'
- 'PayloadsAllTheThings/SSTI (2026 update: error/boolean/time-based detection)'
---


# Velocity SSTI 成立条件（知识库文档）

供 阶段 4 判断；关注 SecureUberspector 与模板来源。**（Java 模板引擎；其他语言/框架的 SSTI 如 Jinja2、Twig、Freemarker、EJS 等可仿照本结构新增文档。）**

---

## 发现条件

- 代码中出现 `Velocity.evaluate()`、`VelocityEngine.evaluate()`、或用户输入作为模板内容传入模板引擎。

## 成立条件

- **SecureUberspector**：
  - 未配置 → 可利用（反射调用 Runtime.exec 等）
  - 已配置 → 检查自定义 Uberspector 是否存在绕过
- **模板内容来源**：
  - 来自用户输入 → 可利用
  - 来自数据库且用户可写 → 可利用
  - 硬编码模板 → 不可利用（但需检查是否有其他模板注入点）

## 配置检查

- 搜索 `SecureUberspector`、`runtime.introspector.uberspect` 等配置；若无法确认则标 **待验证（HYPOTHESIS）**。
