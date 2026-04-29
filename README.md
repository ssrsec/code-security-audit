# code-security-audit

AI 驱动的代码安全审计 Claude Code 插件。只关注有实际危害的漏洞，支持全量审计与组合漏洞攻击链分析，采用 Orchestrator + Agent Team 架构全程自动编排。

## 核心原则

1. **只报有实际危害的漏洞**：RCE、SQL 注入、文件操作、越权、未授权、SSRF 等能获取权限/数据的问题
2. **不报无实际危害的问题**：DoS、CSRF 缺失、Cookie 标记、安全头缺失、代码规范、猜测性风险
3. **全量审计 100% 覆盖**：禁止抽样，逐文件审阅
4. **组合漏洞分析**：单漏洞审计后必须分析攻击链组合
5. **反幻觉**：代码证据为王，路径必须 Glob/Read 验证

## 审计流程

```
阶段 0（度量）→ 阶段 1（侦察）→ 阶段 2（审计）→ 阶段 3（覆盖率）→ 阶段 4（验证）→ 阶段 5（组合）→ 阶段 6（报告）
```

## Agent 架构

```
audit-orchestrator（总编排控制器）
    ├── audit-recon-agent      ← Phase 1 侦察
    ├── audit-sink-agent       ← Phase 2 Sink-driven（与 control 并行）
    ├── audit-control-agent    ← Phase 2 Control-driven（与 sink 并行）
    ├── audit-validate-agent   ← Phase 4 验证 + Phase 5 组合分析
    └── audit-report-agent     ← Phase 6 报告生成 + 清理
```

## 使用方式

```
对 AI 说：「开始审计」或「对 XXX 项目做安全审计」即可启动
```

对话过程中如被中断，发送「继续审计」即可从断点恢复。

## 安装

```bash
# 作为 Claude Code 插件安装（本地路径）
claude --plugin-dir /path/to/code-security-audit

# 或将目录加入 Claude Code 插件配置
```

## 目录结构

```
code-security-audit/
├── .claude-plugin/
│   └── plugin.json                   # 插件清单
├── agents/
│   ├── audit-orchestrator.md         # 总编排控制器
│   ├── audit-recon-agent.md          # Phase 1 侦察
│   ├── audit-sink-agent.md           # Phase 2 Sink-driven
│   ├── audit-control-agent.md        # Phase 2 Control-driven
│   ├── audit-validate-agent.md       # Phase 4+5 验证+组合
│   └── audit-report-agent.md         # Phase 6 报告
├── skills/
│   ├── code-security-audit/          # 主控 skill（总协议）
│   ├── audit-recon/                  # Phase 1 详细规则
│   ├── audit-sink/                   # Phase 2 Sink-driven 详细规则
│   ├── audit-control/                # Phase 2 Control-driven 详细规则
│   ├── audit-validate/               # Phase 4 验证规则（含知识库）
│   └── audit-report/                 # Phase 6 报告规则（含模板）
├── shared/                           # 共享协议与配置
│   ├── anti_hallucination.md         # 反幻觉铁律
│   ├── report_fields.md              # 报告字段定义（严格约束）
│   ├── composite_vulnerability_analysis.md  # 组合漏洞协议
│   ├── scope_policy.md               # 审计范围策略
│   ├── verification_principles.md    # 验证原则
│   ├── decompilation.md              # 反编译预处理
│   ├── dimensions.md                 # 10 个安全维度
│   ├── large_project_audit.md        # 大项目审计约定
│   ├── audit_output_layout.md        # 产出目录约定
│   ├── coverage_matrix_template.md   # 覆盖矩阵模板
│   ├── phase_definitions.md          # 阶段定义
│   ├── config/                       # Tier 规则、文件范围、优先级关键词
│   └── tools/                        # 批次规划脚本
└── scripts/                          # 辅助脚本
```
