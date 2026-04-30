---
last_updated: "2026-04-30"
version: "1.0"
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
