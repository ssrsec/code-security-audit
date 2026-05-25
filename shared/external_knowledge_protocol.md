# 外部知识获取协议（联网搜索 + 文档 MCP）

> **何时必读**：遇到陌生框架、新 CVE、最新 gadget 链、非主流语言/库时；模型对 sink 是否危险/版本是否受影响无法独立判定时。
> **何时不需要读**：审计目标全部是已知主流框架（Spring/Express/Django/Laravel/.NET），且 `shared/sink_catalog_by_lang.md` 已覆盖相关 sink 时。
>
> 本文档定义"何时联网"、"用什么工具"、"如何留证"三件事。

## 1. 工具优先级

按"准确性 × 时效性 × 成本"三维度选用：

| 优先级 | 工具 | 用途 | 何时用 |
|--------|------|------|--------|
| P1 | `Context7 MCP`（如可用） | 框架 / SDK / API 官方文档与最新代码示例 | 框架特定 sink / 鉴权 API 语义不明 |
| P2 | `WebSearch`（Cursor/Claude 内置）| CVE 详情、最新 gadget、社区分析文章 | 反序列化 / 模板注入 / 新发布 CVE |
| P3 | `WebFetch` | 已知 URL（如 NVD 条目、官方 advisory）抓正文 | 已有 CVE-XXXX-XXXXX 编号 |
| P4 | 模型预训练知识 | 主流 sink 与通用模式 | 已覆盖于 `sink_catalog_by_lang.md` 的内容 |

**禁止**：直接编造"经典 gadget"或"通用 CVE 编号"。无外部佐证时一律标「待验证」。

## 2. 触发联网的 7 类场景

| # | 场景 | 推荐查询模板 | 必须取得的证据 |
|---|------|-------------|--------------|
| 1 | 陌生框架的鉴权 API | `<framework> authentication middleware <version>` | 官方 doc URL + 注解/装饰器名 + 默认行为 |
| 2 | 反序列化是否有可用 gadget | `<library> <version> deserialization gadget CVE` | 至少 1 个公开 CVE 编号 + PoC URL（或证明无公开 gadget） |
| 3 | 依赖版本是否在 CVE 影响范围 | `<package> <version> CVE site:nvd.nist.gov` | NVD 编号 + Affected Versions 文本 |
| 4 | 新模板引擎是否支持 SSTI | `<template-engine> SSTI server side template injection` | 公开 PoC 链接或官方 sandbox 文档 |
| 5 | 框架默认配置是否有风险（如 autoType） | `<library> <version> default configuration security` | 官方 changelog 或 advisory URL |
| 6 | LDAP/XPath/NoSQL 等小众注入语法 | `<protocol> injection bypass examples` | 至少 1 个权威示例 |
| 7 | 反编译/混淆代码语义不明 | `<class name> <method signature>` | 至少 1 个开源同名实现可对照 |
| 8 | 审计目标是已知通用系统/产品 | `<系统名> <版本> CVE vulnerability` / `<系统名> 漏洞分析` / `<系统名> default credentials` | 已知 CVE 列表 + 高价值攻击面 + 默认凭证 + 公开 PoC URL |

## 3. 查询纪律（防幻觉）

1. **必须先查再写**：不得"猜个 CVE 编号写上去"。无搜索结果 → 标「待验证」+ 列出"需查 X"。
2. **必须留 URL**：每条引用必须保留来源 URL，写入 finding 的「外部依据」字段。
3. **必须脱敏**：从联网结果摘录的真实 token / IP / 内网域名 → 一律脱敏为 `xxx.example.com / 10.0.0.X`。
4. **不得复制完整 exploit 脚本**：报告中保留"路径概述 + 关键 payload 片段"即可，完整脚本走 `audit/poc/<finding-id>/` 受控目录。
5. **跨源验证**：CVE 描述至少由 2 个独立来源（NVD + 厂商 advisory，或 NVD + GitHub PoC）相互印证后才进入「已确认」。

## 4. 引用格式（写入 finding）

每条联网检索得到的关键事实，在 `validated_findings.md` 中按以下格式标注：

```markdown
**外部依据**：
- [CVE-2024-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX) — Affected: fastjson 1.2.47-1.2.83
- [厂商 advisory](https://github.com/alibaba/fastjson/wiki/security_update_20220523) — 修复版本 1.2.83
- [PoC 示例](https://github.com/...) — JdbcRowSetImpl gadget 链
```

**不允许**只写 "据公开资料"、"业界已知" 等无 URL 的模糊表述。

## 5. 联网失败的降级路径

| 失败原因 | 降级处理 |
|---------|----------|
| 平台无 WebSearch / MCP 工具 | 标「待验证」+ "需人工查 CVE-XXXX 等 N 项"；不得编造 |
| 网络不可达 / 沙箱限制 | 同上；写入 `audit/state.json` "blockers" 字段 |
| 搜索结果与项目场景不匹配 | 仍标「待验证」+ 写明"已查 N 个来源，未找到精确匹配项目场景的证据" |
| 仅找到中文论坛二手描述 | 标「待验证」+ 注明"二手描述未找到原始 CVE"，不升级为「已确认」 |

## 6. 与现有 skill 的接线

- `audit-recon/SKILL.md`：在 "通用系统识别" 步骤中识别到已知系统时按 §2 表 #8 联网查历史漏洞和安全分析文章；在 "依赖/Secret/供应链画像" 步骤中遇到陌生依赖时按 §2 表 #3 联网查 CVE。
- `audit-sink/SKILL.md`：遇到 `shared/sink_catalog_by_lang.md` 未覆盖的 sink API 时按 §2 表 #1/#6 联网查官方语义。
- `audit-validate/SKILL.md`：在 "成立条件复核" 中遇到反序列化 / SSTI / 模板注入需 gadget 信息时按 §2 表 #2/#4 联网查；在引入「外部依据」字段时按 §4 格式。
- `audit-orchestrator.md`：在 prompt 注入时引用本文件，提示子 agent 在缺乏知识时主动联网。

## 7. 不应联网的场景（避免滥用）

- 主流 sink 已在 `sink_catalog_by_lang.md` 覆盖 → 直接用预训练知识
- 通用 OWASP Top 10 概念 → 模型已熟练
- 已有 V2-V4 PoC 证据的漏洞 → 不需要联网佐证
- 业务逻辑漏洞（IDOR / 越权 / 状态机）→ 与项目特定逻辑相关，联网无解

## 8. applicability（模型代际标签）

| 协议条款 | 现状必要性 | 模型 V5+ 后 |
|---------|-----------|------------|
| §2 触发场景表 #1-#7 | 必要（模型预训练截止 + CVE 持续涌现） | 永远必要（除非模型有实时检索能力） |
| §3 查询纪律（防幻觉） | 必要（模型仍会编造） | 长期必要 |
| §4 引用格式 | 必要（报告可追溯性） | 长期必要 |
| §7 不应联网场景 | 必要（控成本） | 长期必要 |
