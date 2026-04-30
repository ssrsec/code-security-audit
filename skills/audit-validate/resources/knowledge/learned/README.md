# 自学习知识库

本目录存放通过审计实践自动沉淀的漏洞模式。

## 文件来源

每次审计完成后，`audit-knowledge-learn` skill 从已验证漏洞（V2+）中提取可泛化的检测模式，
自动写入本目录。

## 文件命名

`{vuln_type}_{framework}_{date}.md`

## 使用方式

Phase 4 验证时，audit-validate-agent 会同时参考主知识库和本目录的文件。

## 合并到主知识库

经人工确认后，可将本目录的文件内容合并到上级目录对应的 `*_conditions.md` 中。
