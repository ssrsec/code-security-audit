---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- PHP反序列化
- unserialize
- phar://
- __wakeup
- __destruct
- POP chain
- gadget
cwe:
- CWE-502
owasp:
- A08:2021
nuclei_tags:
- deserialization
- php
frameworks:
- PHP
vuln_types:
- deserialization
- rce
severity_range:
- critical
references:
- PayloadsAllTheThings/Insecure Deserialization/PHP
---


# PHP unserialize 对象注入成立条件

## 发现条件

- `unserialize($_...)`、`maybe_unserialize`、session 反序列化、自定义反序列化封装。
- 输入来自 Cookie、POST、GET、Header、文件上传、缓存、数据库。

## 成立条件

- 外部可控序列化字符串进入 `unserialize`。
- 项目或依赖中存在可利用魔术方法：`__wakeup`、`__destruct`、`__toString`、`__call`。
- 未使用 `allowed_classes=false` 或严格白名单。

## 验证要求

- 搜索魔术方法和文件/命令/SQL/模板 sink。
- 建立 POP 链或证明业务字段篡改。
- 授权环境中使用无害命令或临时文件证明，执行后清理。

## 报告要点

- 不得只因 `unserialize` 存在就标 RCE。
- 必须写明 POP 链、魔术方法和 sink。
