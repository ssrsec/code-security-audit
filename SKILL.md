---
name: code-security-audit
description: AI 驱动的生产级代码安全审计协议。面向企业内部授权审计，默认使用结构化 harness：项目画像、攻击面枚举、Sink/Control 双轨候选发现、验证队列、能力链、质量门、报告渲染和完整证据交付。支持 PHP、Java、C# / ASP.NET、Go、Python、JavaScript / TypeScript Node.js、Ruby、Rust、Kotlin、Deno/Bun，以及 JVM/.NET 编译产物反编译计划。用户说「开始审计 / 对 XXX 做安全审计 / 代码审计 / 安全扫描 / 找漏洞 / security audit / 红队审计」时触发。
---

# 代码安全审计生产协议

本入口默认执行代码安全审计生产协议。

## 授权与安全边界

本 skill 仅用于企业内部授权的防御性代码安全审计。审计目标、靶场地址、凭据和验证动作必须属于授权范围。

- L1：只读分析和只读请求，默认允许。
- L2：可回滚写操作，授权靶场内默认允许自动执行，必须记录 baseline、proof、cleanup 和 post-cleanup assert。
- L3：不可逆、高破坏或高影响动作，极少使用；只有这类动作才需要逐次明确说明风险并获得当次授权。
- 内部权威报告不脱敏。保留复现所需的 Cookie、Token、路径、payload、响应摘要和业务标识。

## 默认输出

所有新审计默认写入：

```text
audit-v2/
```

Markdown 不是权威状态。权威状态是 SQLite + 结构化 JSON/JSONL，最终报告只由结构化数据渲染生成。

## 支持栈

生产准入覆盖以下常用审计目标：

- PHP。
- Java / Kotlin / JVM 编译产物。
- C# / ASP.NET / .NET 编译产物。
- Go。
- Python。
- JavaScript / TypeScript Node.js。
- TypeScript Deno / Bun。
- Ruby。
- Rust。

JVM 和 .NET 反编译执行链路已接入，但真实执行必须显式传 `--execute`。Android/native 当前只生成明确的反编译计划和 blocker，不假装已支持。

## 生产流程

AI 接到审计请求后必须自动完成环境准备、流水线执行、质量门和报告渲染。工程师只需要提供初始目标信息，以及复杂登录、环境异常、跨平台工具、L3 授权或上下文续跑这类必要交互。

执行审计时按以下生产闭环推进：

1. `recon`：识别语言、框架、入口、source、sink、敏感资产和编译产物。
2. `audit`：生成结构化 V0 candidate findings、callchains、capabilities。
3. `validate`：生成 validation queue，不得无证据升级 confirmed。
4. `chain`：生成 confirmed/hypothesis attack chains，禁止用 hypothesis 支撑 confirmed。
5. `report`：生成 report model。
6. `quality`：执行 schema、semantic、PoC、render、regression gates。
7. `render`：从 report model 渲染完整内部证据报告。
8. `reviewer`：对质量门和交付风险做最终复核。

通用入口：

```bash
python3 tools/audit_pipeline.py \
  --project-root /path/to/project \
  --audit-dir audit-v2 \
  --project-id proj-default \
  --audit-mode redteam
```

`tools/audit_pipeline.py` 会自动创建/使用项目本地 `.venv` 并安装缺失依赖。不得要求工程师手动先执行 bootstrap、pip install 或虚拟环境命令。

## 交付前硬门槛

交付前必须通过离线生产准入：

```bash
python3 tools/production_check.py
```

单个审计目录必须通过：

```bash
python3 quality/quality_gate.py --audit-dir audit-v2 --gate all
python3 quality/quality_gate.py --audit-dir audit-v2 --gate render
```

有 blocker/error 时禁止交付。不得用手写 Markdown 绕过质量门。

## 关键约束

- 禁止编造文件路径、代码片段、调用链、请求包或证据。
- V0/V1 只能作为 candidate/pending，不得写成 confirmed。
- confirmed finding 必须有 evidenceRefs；需要清理的 L2 证明必须有 cleanupRefs。
- PoC 必须给出可复现请求或脚本；HTTP PoC 优先使用 Burp 风格原始请求。
- report model 必须覆盖所有 confirmed/reported/patched findings 和 confirmed chains。
- 渲染报告不得包含 TODO、REPLACE、占位符、空洞代码块或缺失引用标记。
- workers 只写结构化片段，不直接手写最终报告。

## 文档入口

执行审计前按需读取：

- `protocol/workflow.md`
- `protocol/state.md`
- `protocol/live-target.md`
- `protocol/evidence-output.md`

资产入口：

- `assets/manifest.json`

## 完成标准

一次审计只有在以下条件满足后才算完成：

- 结构化状态和 JSON/JSONL 产物完整。
- quality gate 和 render gate 通过。
- reviewer 未给出阻断结论。
- 最终报告已由 `report/render_report.py` 渲染到 `audit-v2/reports/security_audit_report.md`。
- 所有待验证项、限制、未执行的 live target 操作都写入 report model limitations。
