# code-security-audit

面向企业内部授权场景的 AI 代码安全审计框架。

你可以把它安装到 Cursor / Agent 的技能目录里，然后直接对 AI 说“开始审计”。工程师通常只需要提供初始信息，例如目标代码路径、审计模式、靶场地址、测试账号、凭据或范围约束；环境准备、虚拟环境、依赖安装、审计流水线、质量门和报告渲染都由 AI 按协议自动完成。

给 AI 的执行入口是 `SKILL.md`。本 README 只面向 GitHub 用户介绍项目。

## 项目目标

传统 AI 代码审计很容易变成“长 prompt + 人工 Markdown 报告”，常见问题包括：

- 漏洞证据不可追溯。
- PoC 描述不完整。
- 报告里出现占位符或表格裂行。
- 旧上下文丢失后无法恢复。
- 复杂项目需要工程师反复手动推进。
- 依赖安装污染用户全局环境。

本项目把审计过程收敛为结构化协议：

- SQLite 作为权威状态。
- JSON / JSONL 作为审计产物和事件导出。
- JSON Schema 约束核心字段。
- quality gate 阻断结构错误、语义矛盾、坏 PoC 和坏报告。
- report renderer 只从结构化数据生成最终报告。
- 本地 `.venv` 自动隔离 Python 依赖。

## 使用方式

### Cursor

将本仓库放到 Cursor skills 目录，例如：

```text
~/.cursor/skills/code-security-audit/
```

或作为项目级 skill 放到目标项目的 `.cursor/skills/code-security-audit/`。

打开目标项目后，在 Cursor 里直接对 AI 说：

```text
开始审计
```

如果本仓库不是放在目标项目内，也可以明确提供审计目标路径。

### Claude Code

将本仓库放到 Claude Code 可读取的技能 / 插件目录，或在启动 Claude Code 时让当前会话能访问本仓库。

然后在目标项目上下文中对 AI 说：

```text
对当前项目做安全审计
```

如果你的 Claude Code 环境不自动加载 `SKILL.md`，可以在提示中明确说明：

```text
请使用 /path/to/code-security-audit/SKILL.md 作为审计协议，对 /path/to/project 做安全审计
```

### Trae / 其他 AI IDE

把本仓库作为可读目录加入工作区，或复制到该 IDE 支持的 Agent Skill / Rules / Knowledge 目录中。

核心要求只有两个：

1. AI 能读取本仓库的 `SKILL.md`。
2. AI 能在本机执行 Python 脚本。

之后对 AI 说：

```text
使用 code-security-audit，对 /path/to/project 开始审计
```

### 触发示例

在 Cursor / Agent 中触发审计时，直接说：

```text
开始审计
```

或：

```text
对 /path/to/project 做安全审计
```

带靶场时可以说：

```text
对 /path/to/project 做红队审计，靶场是 http://127.0.0.1:8080，测试账号是 test / test123
```

AI 会自动：

1. 读取 `SKILL.md`。
2. 创建或复用项目本地 `.venv`。
3. 安装缺失依赖到 `.venv`。
4. 识别项目语言、框架、入口、source、sink、secret 和编译产物。
5. 生成结构化候选 finding、callchain、capability 和 validation queue。
6. 按授权等级执行本地或靶场验证。
7. 生成 report model。
8. 运行质量门和渲染门。
9. 渲染最终报告。

最终报告默认输出到：

```text
audit-v2/reports/security_audit_report.md
```

## 工程师何时需要介入

正常情况下，工程师提供初始信息后等待报告即可。

只有以下情况需要工程师介入：

- 复杂登录、MFA、验证码、SSO、设备绑定等 AI 无法自动完成的认证场景，需要提供 Cookie、Token、会话生成步骤或已登录测试状态。
- 靶场或环境异常，例如服务未启动、网络不可达、版本不一致、测试数据缺失、部署不完整。
- 当前操作系统不支持某些验证工具，需要工程师在其他环境运行并回传结果。
- L3 不可逆或高破坏动作，需要逐次明确授权。
- AI 单次上下文耗尽，需要工程师发送“继续审计”。

除此之外，环境准备、脚本执行、质量门和报告生成都不应要求工程师手动处理。

## 支持技术栈

当前生产准入覆盖：

- PHP
- Java / Kotlin
- C# / ASP.NET
- Go
- Python
- JavaScript / TypeScript（Node.js）
- TypeScript（Deno / Bun）
- Ruby
- Rust
- JVM / .NET 编译产物的反编译计划与 dry-run wrapper

JVM 和 .NET 真实反编译执行需要显式安全参数；Android/native 当前只生成明确计划和限制说明，不伪造覆盖率。

## 安全边界

本项目只用于合法授权的防御性安全测试。

- L1：只读分析和只读请求，默认允许。
- L2：可回滚写操作，在已授权靶场内默认由 AI 自动执行，必须记录 baseline、proof、cleanup 和 post-cleanup assert。
- L3：不可逆或高破坏动作，极少使用；只有这类动作才需要逐次明确授权。

内部权威报告默认不脱敏，以保证复现、验证和修复所需证据完整。

## 核心目录

```text
SKILL.md                    # AI 默认执行入口
assets/                     # payload、能力、攻击链、反编译等 canonical 资产
protocol/                   # 工作流、状态、靶场、证据和失败恢复协议
schemas/                    # 结构化产物 JSON Schema
state/                      # SQLite 状态层
quality/                    # 质量门
report/                     # 报告渲染器
tools/                      # 审计流水线、HTTP replay、反编译、生产准入等工具
workers/                    # recon / audit / validate / chain / report / reviewer
examples/                   # 回归样本
scripts/tools/decompilers/  # JVM / .NET 反编译 wrapper
```

## 质量保障

生产准入覆盖：

- 本地 `.venv` runtime guard。
- Python 文件编译。
- assets manifest 与子 manifest。
- bootstrap 环境检查。
- EMS regression。
- generic pipeline。
- 目标语言矩阵。
- 当前仓库 self pipeline。
- HTTP replay dry-run 与 L2 guard。
- dispatcher smoke。
- JVM / .NET decompilation dry-run。
- root entrypoint guard。
- packaging guard。

如果生产准入失败，AI 不应交付最终报告。

## 开源使用声明

本仓库包含安全审计和漏洞验证相关能力。请仅在合法授权范围内使用，并确认目标系统、账号、靶场、数据和验证动作均已获得授权。
