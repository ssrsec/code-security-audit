# code-security-audit

AI 驱动的代码安全审计框架。支持 redteam/full 两种模式，支持靶场集成验证，采用 Orchestrator + Agent Team 架构全程自动编排。

## 核心特性

- **双模式审计**：redteam（只看安全控制类漏洞）/ full（含业务逻辑漏洞）
- **靶场集成**：提供靶场地址后自动构造真实请求验证漏洞
- **通用系统识别**：自动识别已知系统（RuoYi/Jenkins/WordPress 等）并搜索历史漏洞
- **全量覆盖**：禁止抽样，三层覆盖率分别记录
- **双轨组合分析**：漏洞×漏洞 + 原语×原语 两条独立推导路径
- **反幻觉**：代码证据为王，路径必须 Glob/Read 验证

## 使用方式

```
# 全量审计（默认）
对 AI 说：「开始审计」或「对 XXX 项目做安全审计」

# 红队模式（跳过纯业务逻辑漏洞）
对 AI 说：「红队审计 XXX」或「对 XXX 做 redteam 审计」

# 带靶场验证
对 AI 说：「审计 XXX，靶场 http://10.0.0.5:8080，账号 admin/admin123」

# 中断后恢复
对 AI 说：「继续审计」

# 从指定阶段恢复
对 AI 说：「从阶段 4 继续」
```

## 审计模式

| 模式 | 关注范围 | 适用场景 |
|------|---------|---------|
| **redteam** | 所有突破安全控制的漏洞（RCE/注入/认证绕过/越权/SSRF 等） | 渗透测试辅助、快速风险评估 |
| **full** | redteam 全部 + 纯业务逻辑漏洞（支付篡改/状态机跳跃/库存绕过等） | 全面安全评估、合规审计 |

两种模式的唯一区别：是否审计**纯业务逻辑缺陷**。安全控制类漏洞在两种模式下都审。

## 审计流程

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6
参数解析   侦察     双轨审计   质量门     验证       组合分析   报告
+度量     +系统识别 (Sink‖    +覆盖率    +靶场验证  (漏洞组合   +质量检查
+反编译   +情报收集  Control) +去重                 ‖原语组合)
```

## Agent 架构

```
audit-orchestrator（总编排控制器）
    ├── audit-recon-agent       ← Phase 1 侦察 + 通用系统识别
    ├── audit-sink-agent        ← Phase 2 Sink-driven（与 control 并行）
    │    └── primitives_batch    （同时发射原语）
    ├── audit-control-agent     ← Phase 2 Control-driven（与 sink 并行）
    │    └── primitives_batch    （同时发射原语）
    ├── audit-validate-agent    ← Phase 4 单漏洞验证
    ├── audit-composite-agent   ← Phase 5 漏洞组合（与 primchain 并行）
    ├── audit-primchain-agent   ← Phase 5 原语组合（与 composite 并行）
    └── audit-report-agent      ← Phase 6 报告生成
```

## 报告输出

| 条件 | 输出形式 |
|------|---------|
| 漏洞总数 ≤ 20 | 单文件 `audit/security_audit_report.md` |
| 漏洞总数 > 20 | 主报告 + 每条漏洞独立文件 `audit/findings/vul-NNN.md` |

## 安装

### Cursor

将本目录置于项目根的 `.cursor/skills/` 下。orchestrator 会自动检测平台并使用 Task 工具调度子 Agent。

### Claude Code

```bash
claude --plugin-dir /path/to/code-security-audit
```

## 目录结构

```
code-security-audit/
├── SKILL.md                            # 总控协议（审计模式/报告策略/核心原则）
├── agents/                             # Agent 接口文件（触发条件+输入输出+指向 SKILL）
│   ├── audit-orchestrator.md           # 总编排控制器
│   ├── audit-recon-agent.md            # Phase 1 侦察
│   ├── audit-sink-agent.md             # Phase 2 Sink-driven
│   ├── audit-control-agent.md          # Phase 2 Control-driven
│   ├── audit-validate-agent.md         # Phase 4 验证
│   ├── audit-composite-agent.md        # Phase 5 漏洞组合
│   ├── audit-primchain-agent.md        # Phase 5 原语组合
│   └── audit-report-agent.md           # Phase 6 报告
├── skills/                             # 各阶段详细规则（行为定义的单一事实来源）
│   ├── audit-recon/SKILL.md
│   ├── audit-sink/SKILL.md
│   ├── audit-control/SKILL.md
│   ├── audit-primitives/SKILL.md
│   ├── audit-validate/SKILL.md         # 含 resources/knowledge/ 知识库
│   ├── audit-composite/SKILL.md
│   └── audit-report/SKILL.md           # 含 resources/report_template.md
├── shared/                             # 跨阶段共享协议
│   ├── phase_definitions.md            # 阶段定义
│   ├── audit_discipline.md             # 反幻觉 + 审计范围
│   ├── report_fields.md                # 报告字段定义
│   ├── coverage_policy.md              # 覆盖率策略（D1-D10 维度）
│   ├── verification_principles.md      # V0-V4 验证原则
│   ├── decompilation.md                # 反编译三级降级策略
│   ├── external_knowledge_protocol.md  # 联网搜索协议
│   ├── sink_catalog_by_lang.md         # 各语言危险 Sink 速查
│   ├── framework_catalog.md            # 框架/鉴权速查
│   ├── poc_policy.md                   # PoC 安全策略
│   ├── taint_propagation.md            # 污点传播规则
│   ├── sink_reachability_checklist.md  # R1-R7 可达性算法
│   └── ...                             # 其他共享文档
├── scripts/
│   ├── quality_check.py                # 报告质量自检（Phase 4/6 自动调用）
│   ├── coverage_diff.py                # 覆盖率差异计算
│   ├── tier_classify.py                # Tier 分类辅助
│   └── tools/payload_templates/        # 9 个 payload 模板知识库
└── rules/                              # Cursor 规则文件
```
