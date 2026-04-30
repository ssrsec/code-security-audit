---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- 命令注入
- OS注入
- command injection
- RCE
- Runtime.exec
- ProcessBuilder
- os.system
- subprocess
- child_process
- exec
- shell injection
- code execution
cwe:
- CWE-78
- CWE-77
cwe_rank: 9
owasp:
- A03:2021
nuclei_tags:
- rce
- command-injection
frameworks:
- Java
- Python
- PHP
- Node.js
- Go
- .NET
vuln_types:
- injection
- command_injection
- rce
severity_range:
- high
- critical
references:
- 'CWE Top 25 #9 (2025)'
- PayloadsAllTheThings/Command Injection
---


# 命令注入 / 操作系统注入成立条件（通用）

供 阶段 4 判断；**框架无关**，属 **OWASP Top 10 A03:2021 Injection**。适用于任意语言与框架。

---

## 发现条件

- 代码中**执行系统命令、 shell、或调用外部程序**，且命令字符串或参数的一部分**来自用户输入、配置或不可信数据**（如拼接、格式化、或未做严格白名单的 API）。

---

## 成立条件（按写法）

- **拼接/格式化**：`exec(cmd)`、`Runtime.getRuntime().exec("sh -c " + userInput)`、`os.system("ping " + host)`、`child_process.exec("ls " + dir)`、`Process.Start("cmd", "/c " + input)` 等 → 若输入未严格校验（如仅允许数字/字母），成立。
- **参数未隔离**：即使使用参数列表形式（如 `exec(["ping", "-c", "1", host])`），若 `host` 用户可控且未校验（如可含 `; id`），仍可能成立。
- **二次注入**：用户输入先落库或进配置文件，再由脚本/定时任务执行 → 需追踪完整数据流。
- **白名单/安全 API**：若仅允许固定命令+白名单参数（如只允许数字 ID），或使用不解析 shell 的 API 且参数列表化，则风险低；需 Read 确认。

---

## 如何确认

- **Read 代码**：定位执行命令的 API（exec、system、shell_exec、eval、ProcessBuilder、subprocess、child_process、Process.Start 等），向上追踪参数来源。
- **多语言示例**：Java Runtime.exec/ProcessBuilder、Python os.system/subprocess、PHP exec/shell_exec/passthru、Node child_process、Go os/exec、.NET Process。
- **报告约定**：注明「文件:行号」、参数来源、是否有校验；若存在 WAF/输入过滤但无法确认，标 **待验证（HYPOTHESIS）**。

---

## 与“真实危害”范围

- 可执行任意命令（RCE）→ 在默认 scope 内，High/Critical。
- 仅可执行受限命令（如仅 ping）→ 按影响标 Medium/Low。
