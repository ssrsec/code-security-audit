# Evidence Output Protocol

## 原则

内部权威报告和证据包不脱敏。所有用于复现、验证和修复的关键数据必须保留。

## 必须保留

- 完整 HTTP 请求。
- 完整关键响应摘要。
- Cookie、Token、session id。
- 密码哈希。
- 文件路径。
- 数据库用户、版本、schema、表名、列名。
- 业务 ID。
- L2 mutation 和 cleanup 证据。

## 不自动脱敏

核心流程不生成自动脱敏报告，不在生成阶段弱化 payload、响应或证据。

如未来需要对外交付脱敏版本，必须作为独立后处理工具实现，不得影响内部权威报告和证据包。

## 报告引用

报告中引用 request/evidence/capability 时必须使用结构化 ID，而不是自然语言“见上一步”。

## 禁止

- `REDACTED_JWT`
- `Cookie: (同上)`
- `<上一步 sessionId>`
- `REPLACE_WITH_VALID_TOKEN`
- 因担心敏感而省略 payload。
- 将真实证据替换为模糊描述。
