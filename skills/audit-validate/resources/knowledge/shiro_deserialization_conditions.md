---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- Shiro
- RememberMe
- 反序列化
- AES
- CBC
- DefaultSerializer
- 硬编码密钥
cwe:
- CWE-502
- CWE-321
owasp:
- A08:2021
- A02:2021
nuclei_tags:
- deserialization
- shiro
- rce
frameworks:
- Java
vuln_types:
- deserialization
- rce
- hardcoded_key
severity_range:
- critical
references:
- Nuclei-templates shiro
---


# Apache Shiro RememberMe 反序列化条件

## 发现条件

- 项目使用 Apache Shiro。
- 开启 RememberMe 或存在 `rememberMe` cookie 处理。
- 代码或配置出现默认/硬编码 `cipherKey`。

## 成立条件

- 使用历史受影响 Shiro 版本或不安全 RememberMe 配置。
- AES cipher key 为默认值、公开值或硬编码可获取。
- classpath 存在可利用 Java gadget 链。

## 验证要求

- 查 Shiro 版本、`securityManager`、`rememberMeManager`、`cipherKey`。
- 查是否可向目标发送 rememberMe cookie。
- 查 classpath gadget。
- 授权测试环境中使用无害命令或 mock gadget 验证，不输出真实攻击载荷到非授权环境。

## 报告要点

- Shiro key 必须脱敏。
- 如果只有版本线索但无 key/gadget/入口，最多 V1 待验证。
