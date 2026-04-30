---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- Java原生反序列化
- ObjectInputStream
- readObject
- Serializable
- gadget chain
- ysoserial
- Commons Collections
- Spring
- BeanUtils
cwe:
- CWE-502
owasp:
- A08:2021
nuclei_tags:
- deserialization
- java
frameworks:
- Java
vuln_types:
- deserialization
- rce
severity_range:
- critical
references:
- PayloadsAllTheThings/Insecure Deserialization/Java
- ysoserial (6.8k stars)
---


# Java 原生反序列化成立条件

## 发现条件

- `ObjectInputStream.readObject`、`readUnshared`、RMI/JMX/JMS/HTTP session 反序列化。
- 输入来自网络、文件上传、缓存、MQ、数据库或可污染内部源。

## 成立条件

- 外部可控字节流到达 `readObject`。
- 未使用 JEP 290 ObjectInputFilter 或自定义白名单。
- classpath 存在可利用 gadget，或项目自定义 `readObject/readResolve` 有危险副作用。

## 验证要求

- 查调用链、输入源和过滤器配置。
- 查 JDK 版本、依赖列表和 gadget 候选。
- 授权环境中使用无害命令或 mock gadget 验证。
- 没有 gadget 或过滤器无法确认时标 V1 待验证。

## 报告要点

- 不得把所有 `readObject` 都当 RCE。
- 必须写明过滤器、依赖、输入源和 gadget 证据。
