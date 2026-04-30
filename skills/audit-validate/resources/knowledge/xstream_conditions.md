---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- XStream
- XML反序列化
- XML deserialization
- fromXML
- SecurityFramework
- allowedTypes
cwe:
- CWE-502
owasp:
- A08:2021
nuclei_tags:
- deserialization
- xstream
frameworks:
- Java
vuln_types:
- deserialization
- rce
severity_range:
- critical
references:
- PayloadsAllTheThings/Insecure Deserialization
---


# XStream 反序列化成立条件

## 发现条件

- 代码中存在 `XStream.fromXML`、`fromXML(InputStream)`、`unmarshal`。
- XML 输入来自 HTTP、MQ、Redis、DB、文件上传、第三方回调或可污染的内部源。

## 成立条件

- XStream 版本较旧，未启用类型白名单或安全框架。
- 使用默认 `XStream` 配置，未调用 `allowTypes`、`allowTypesByWildcard`、`denyTypes`、`setupDefaultSecurity`。
- classpath 存在可利用类型或项目自定义类型存在危险构造、setter、readResolve、动态代理链。

## 验证要求

- 确认版本来源：`pom.xml`、`build.gradle`、`WEB-INF/lib/xstream-*.jar`。
- 确认 XML 输入能外部控制。
- 有测试环境时使用无害命令或 mock gadget 证明执行路径。
- 无法确认 gadget 或安全配置时标 V1 待验证。

## 报告要点

- 写明 XStream 版本、配置、输入来源、允许/拒绝类型策略、classpath 证据。
- 不得只因存在 `fromXML` 就标已确认 RCE。
