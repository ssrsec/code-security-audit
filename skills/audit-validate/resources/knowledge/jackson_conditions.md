---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- Jackson
- 多态反序列化
- polymorphic deserialization
- ObjectMapper
- enableDefaultTyping
- JsonTypeInfo
- gadget
- PolymorphicTypeValidator
cwe:
- CWE-502
owasp:
- A08:2021
nuclei_tags:
- deserialization
- jackson
frameworks:
- Java
vuln_types:
- deserialization
- rce
severity_range:
- high
- critical
references:
- PayloadsAllTheThings/Insecure Deserialization
---


# Jackson 多态反序列化成立条件

## 发现条件

- 代码启用 default typing：`enableDefaultTyping`、`activateDefaultTyping`。
- 使用 `@JsonTypeInfo` 且类型名可由外部输入控制。
- ObjectMapper 反序列化输入来自 HTTP、MQ、Redis、DB、文件或第三方回调。

## 成立条件

- 多态类型未限制到可信基类或白名单。
- 版本存在已知 gadget 影响，且 classpath 中存在相关依赖。
- 反序列化结果可触发危险类型初始化、setter、构造器、副作用方法或业务权限字段篡改。

## 验证要求

- 查 `ObjectMapper` 配置和模块注册。
- 查 Jackson 版本和 classpath gadget。
- 验证 payload 类型字段是否能到达 ObjectMapper。
- 无法确认 gadget 时标 V1 待验证；能证明业务对象属性篡改则可按业务逻辑漏洞验证。

## 报告要点

- 区分“多态 RCE”和“数据篡改/权限字段污染”。
- 写明类型字段、目标类、输入路径和安全配置。
