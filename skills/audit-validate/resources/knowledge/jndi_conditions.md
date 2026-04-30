---
last_updated: "2026-04-30"
version: "1.0"
---

# JNDI 注入成立条件（知识库文档）

供 阶段 4 判断；结合 **JDK/运行环境** 版本与 classpath 依赖。**（Java 生态；其他语言/框架的“远程加载/命名服务”类漏洞可仿照本结构新增文档。）**

---

## 发现条件

- 用户可控输入传入 `InitialContext.lookup(...)`、`JdbcRowSetImpl`、`setDataSourceName` 等 JNDI 相关调用。

## 成立条件（按 JDK 版本）

- **JDK &lt; 8u191**：默认可远程类加载，直接可利用。
- **JDK ≥ 8u191**：trustURLCodebase 默认 false，需本地 Gadget：
  - classpath 有 Tomcat → BeanFactory + ELProcessor 等可利用
  - classpath 有 Groovy → GroovyClassLoader 可利用
  - 若有 SecurityManager → 需检查权限配置

## 如何获取 JDK / 运行环境版本

- 项目配置、CI 配置、Dockerfile 中的 **Java/JDK** 版本；或注明「运行环境 JDK 待确认」并标 **待验证（HYPOTHESIS）**。
