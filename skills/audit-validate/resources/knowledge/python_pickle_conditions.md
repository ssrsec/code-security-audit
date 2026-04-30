---
last_updated: '2026-04-30'
version: '1.0'
keywords:
- pickle
- Python反序列化
- PyYAML
- yaml.load
- marshal
- __reduce__
- shelve
- cPickle
cwe:
- CWE-502
owasp:
- A08:2021
nuclei_tags:
- deserialization
- python
frameworks:
- Python
vuln_types:
- deserialization
- rce
severity_range:
- critical
references:
- 'PayloadsAllTheThings/Insecure Deserialization/Python (2026 update: eval-based universal
  payload)'
---


# Python Pickle / PyYAML 反序列化成立条件

## 发现条件

- `pickle.loads/load`、`dill.loads`、`joblib.load`、`yaml.load`。
- 输入来自 HTTP、上传文件、缓存、MQ、任务队列、模型文件、第三方回调。

## 成立条件

- 外部可控数据直接进入不安全反序列化。
- 未使用安全格式替代，如 JSON、SafeLoader、受限 schema。
- 结果对象可触发 `__reduce__`、导入副作用或业务字段污染。

## 验证要求

- 追踪输入源和文件/消息来源。
- 授权环境中使用无害命令 `whoami` / `id` 或 mock 函数断言。
- 模型文件场景要确认攻击者能上传或替换模型文件。

## 报告要点

- 区分“用户上传模型文件导致 RCE”和“本地可信模型加载”。
- 无外部可控路径时不进入漏洞表。
