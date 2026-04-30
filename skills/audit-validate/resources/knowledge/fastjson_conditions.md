---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- Fastjson
- 反序列化
- autoType
- deserialization
- parseObject
- JSON.parse
- gadget chain
- JNDI
- RMI
- LDAP
cwe:
- CWE-502
owasp:
- A08:2021
nuclei_tags:
- deserialization
- fastjson
- rce
frameworks:
- Java
vuln_types:
- deserialization
- rce
severity_range:
- critical
references:
- PayloadsAllTheThings/Insecure Deserialization
- Nuclei-templates fastjson (12.1k stars)
---


# Fastjson 反序列化成立条件（知识库文档）

供阶段 4 判断使用；AI 阅读后结合项目版本/配置自行判断，非规则引擎。**（Java 生态；其他语言/框架的反序列化、JSON 库可仿照本结构新增对应文档。）**

---

## 发现条件

- 代码中出现 `JSON.parseObject(...)`、`JSON.parse(...)`、或可被用户控制的 JSON 反序列化入口。

## 重要降噪：指定目标类型（Typed parse）通常不等于可利用 RCE

以下场景应**默认降低严重程度**或仅记为 Info/待验证（除非你能证明存在可行利用链）：
- `JSON.parseArray(input, SomeClass.class)`
- `JSON.parseObject(input, SomeClass.class)`

原因：指定目标类型时，常见 AutoType 利用路径会显著收缩，很多情况下更接近"输入校验/资源消耗风险"而不是可直接 RCE。

**输出建议**：
- 若仅发现 typed parse 且无 `@type`/AutoType/Feature 配置证据：优先不纳入"真实危害"清单，或标为 **Info**。
- 若同时满足「版本极旧 + 存在可证明的 Gadget/Feature/配置」：按 V1-V4 验证等级提升为 **待验证（HYPOTHESIS）/已确认（CONFIRMED）**。

## 成立条件（按版本）

- **< 1.2.68**：直接可利用（多条公开利用链）。
- **1.2.68–1.2.80**：检查 classpath 是否有特定依赖：
  - groovy → 可利用
  - jython + postgresql → 可利用
  - aspectj → 可利用
  - commons-io ≥ 2.x → 可利用
- **≥ 1.2.83**：检查 safeMode 配置：
  - safeMode = true → 不可利用
  - safeMode = false + autoType = true → 可利用
  - safeMode = false + autoType = false → 需进一步分析 expectClass 等绕过

## 如何获取版本

- **Maven**：`pom.xml` 或 `dependency-tree` 中 `com.alibaba:fastjson` 版本。
- **Gradle**：`build.gradle` 中 `com.alibaba:fastjson` 版本。
- **lib / 依赖目录检查（无构建文件时）**：当项目无 pom.xml、build.gradle 或无法从构建产物确定版本时，必须扫描**该技术栈常见依赖目录**，根据 **jar 文件名** 提取版本号并写入审计结论：
  - **Java / Servlet**：`lib/`、`WebRoot/WEB-INF/lib/`、`WEB-INF/lib/`、`src/main/webapp/WEB-INF/lib/`。
  - **其他语言**：Node 看 `package.json`/`package-lock.json`；Python 看 `requirements.txt`/`Pipfile.lock`/`site-packages`；PHP 看 `composer.json`/`vendor`；Go 看 `go.mod`/`go.sum`（Fastjson 为 Java 专用，此处仅说明「版本获取方式」可跨技术栈复用）。
  - **识别方式**：查找文件名匹配 `fastjson-*.jar` 或 `fastjson*.jar` 的包；版本号通常为文件名中最后一个 `-` 与 `.jar` 之间的部分（如 `fastjson-1.2.6.jar` → 1.2.6）。
  - **报告要求**：若通过依赖目录确认版本，在漏洞条目的「触发条件」或「漏洞原理」中明确写出：**「依赖目录已检查到 fastjson-x.y.z.jar」**，并据此给出成立条件与严重程度（例如：版本 < 1.2.25 存在已知漏洞，但使用指定类型 parse，利用难度大 → Low）。
- 若**所有途径**均无法确定版本，标为 **V1 待验证（HYPOTHESIS）** 并注明「版本待确认」；如果连危险 API 输入来源都无法闭环，则保持 V0 候选线索。
