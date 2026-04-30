# Code Security Audit — Cursor Plugin

AI 驱动的代码安全审计框架，封装为标准 Cursor 插件。只关注有实际危害的漏洞，支持组合漏洞攻击链分析，采用 Orchestrator + Agent Team 架构全程自动编排。

## 核心原则

1. **只报有实际危害的漏洞** — RCE、SQL 注入、文件操作、越权、未授权、SSRF 等
2. **低影响问题默认不进漏洞表** — DoS、CSRF、Cookie 标记等仅在证明具体影响时才收录
3. **全量审计 100% 覆盖** — 禁止抽样，逐文件审阅，三层覆盖率分别记录
4. **组合漏洞分析** — 单漏洞审计后必须分析攻击链组合
5. **反幻觉** — 代码证据为王，路径必须 Glob/Read 验证

## 审计流程

```
Phase 0（度量）→ Phase 1（侦察）→ Phase 2（双轨审计）→ Phase 3（覆盖率）→ Phase 4（验证）→ Phase 5（组合）→ Phase 6（报告）
```

## Agent 架构

```
audit-orchestrator（总编排）
├── audit-recon-agent        ← Phase 1 侦察
├── audit-sink-agent         ← Phase 2 Sink-driven（与 control 并行）
├── audit-control-agent      ← Phase 2 Control-driven（与 sink 并行）
├── audit-advisor-agent      ← Phase 2 独立监督纠偏（TCH 借鉴）
├── audit-validate-agent     ← Phase 4 验证 + Phase 5 组合分析
├── audit-composer-agent     ← Phase 5 原语汇聚 + 组合链推导
└── audit-report-agent       ← Phase 6 报告生成
```

## 使用方式

对 AI 说「开始审计」或「对 XXX 项目做安全审计」即可启动。对话过程中如被中断，发送「继续审计」可从断点恢复。

## 安装

### Cursor

将本目录置于项目根的 `.cursor/plugins/` 下，或通过 Marketplace 安装：

```bash
# 本地开发测试
ln -s /path/to/cursor_plugin ~/.cursor/plugins/local/code-security-audit
```

### Claude Code

```bash
claude --plugin-dir /path/to/cursor_plugin
```

## 目录结构

```
cursor_plugin/
├── .cursor-plugin/plugin.json       # Cursor 插件清单
├── .claude-plugin/plugin.json       # Claude Code 兼容清单
├── SKILL.md                         # 顶层 skill 入口
│
├── skills/                          # 技能定义（7 个）
│   ├── code-security-audit/         # 总控 skill（唯一入口）
│   ├── audit-recon/                 # Phase 1 侦察
│   ├── audit-sink/                  # Phase 2 Sink-driven
│   ├── audit-control/               # Phase 2 Control-driven
│   ├── audit-primitives/            # Phase 2 原语格式
│   ├── audit-validate/              # Phase 4 验证（含知识库）
│   └── audit-report/                # Phase 6 报告（含模板）
│
├── agents/                          # Agent 定义（8 个）
│   ├── audit-orchestrator.md        # 总编排
│   ├── audit-recon-agent.md         # Phase 1
│   ├── audit-sink-agent.md          # Phase 2 Sink
│   ├── audit-control-agent.md       # Phase 2 Control
│   ├── audit-advisor-agent.md       # Phase 2 监督纠偏
│   ├── audit-validate-agent.md      # Phase 4+5
│   ├── audit-composer-agent.md      # Phase 5
│   └── audit-report-agent.md        # Phase 6
│
├── rules/                           # Cursor 规则（3 个）
│   ├── audit-quality.mdc            # 反幻觉铁律
│   ├── audit-workflow.mdc           # 工作流约束
│   └── audit-report.mdc             # 报告格式约束
│
├── shared/                          # 内部共享协议
│   ├── audit_discipline.md          # 审计纪律
│   ├── coverage_policy.md           # 覆盖率策略（10 维度）
│   ├── phase_definitions.md         # 阶段定义
│   ├── platform_dispatch.md         # 跨平台调度策略
│   ├── poc_policy.md                # PoC 安全与证据
│   ├── verification_principles.md   # 验证原则
│   ├── report_fields.md             # 报告字段定义
│   ├── config/                      # 配置文件
│   └── tools/                       # 辅助脚本
│
├── scripts/                         # 辅助脚本
└── docs/                            # 项目文档
```

## 质量保障

### 三层防线

| 层级 | 组件 | 职责 |
|------|------|------|
| 第一层 | Rules（自动激活） | 反幻觉铁律、工作流约束、报告格式 |
| 第二层 | Skills（Agent 判断） | 降噪规则、覆盖率策略、V0-V4 验证分级 |
| 第三层 | Orchestrator（编排保障） | 产出验证、失败恢复、精确覆盖率 |

### 反幻觉 5+1 铁律

1. 报告漏洞前必须 Glob/Read 验证文件存在
2. 代码片段必须来自 Read 输出
3. 调用链每跳标注文件:行号
4. 不确定标「待验证」不标「已确认」
5. 不确定 ≠ 丢弃
6. 禁止虚报目录不存在

## 双平台适配

| 组件 | Cursor | Claude Code |
|------|--------|-------------|
| Skills | 自动发现，Agent Decides | 从 skills/ 读取 |
| Agents | 自动发现，Agent 选择器可见 | 从 agents/ 读取 |
| Rules | 按 globs 匹配自动激活 | 不适用 |
| shared/ | 由 skill/agent 主动 Read | 由 skill/agent 主动 Read |
| 调度 | Task(generalPurpose) | Agent(name) |
