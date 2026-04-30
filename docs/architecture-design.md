# Code-Security-Audit Cursor Plugin 架构设计报告

## 一、项目定位

将 `code-security-audit` 技能体系封装为标准 Cursor 插件，同时保持 Claude Code 兼容性。支持通过 Cursor Marketplace 分发。

---

## 二、架构总览

```
cursor_plugin/                          ← 插件根目录
├── .cursor-plugin/plugin.json          ← Cursor 插件清单
├── .claude-plugin/plugin.json          ← CC 兼容清单
│
├── skills/                             ← 技能定义（8 个）
│   ├── code-security-audit/SKILL.md    ← 总控 skill（唯一入口）
│   ├── audit-recon/SKILL.md            ← Phase 1 侦察
│   ├── audit-sink/SKILL.md             ← Phase 2 Sink-driven（含 FSM 循环）
│   ├── audit-control/SKILL.md          ← Phase 2 Control-driven（含 FSM 循环）
│   ├── audit-validate/                 ← Phase 4 验证
│   │   ├── SKILL.md
│   │   └── resources/knowledge/        ← 漏洞条件知识库（含版本标记）
│   │       └── learned/                ← 自学习沉淀目录
│   ├── audit-report/                   ← Phase 6 报告
│   │   ├── SKILL.md
│   │   └── resources/report_template.md
│   ├── audit-primitives/SKILL.md       ← Phase 2 原语格式
│   └── audit-knowledge-learn/SKILL.md  ← Phase 7 知识自学习
│
├── agents/                             ← Agent 定义（8 个）
│   ├── audit-orchestrator.md           ← 总编排（含模型路由、评估循环）
│   ├── audit-recon-agent.md            ← Phase 1
│   ├── audit-sink-agent.md             ← Phase 2
│   ├── audit-control-agent.md          ← Phase 2
│   ├── audit-advisor-agent.md          ← Phase 2.5 独立监督
│   ├── audit-validate-agent.md         ← Phase 4+5（含 DAST 可选集成）
│   ├── audit-composer-agent.md         ← Phase 5
│   └── audit-report-agent.md           ← Phase 6
│
├── rules/                              ← Cursor 规则（3 个）
│   ├── audit-quality.mdc               ← 反幻觉铁律
│   ├── audit-workflow.mdc              ← 工作流约束
│   └── audit-report.mdc               ← 报告格式约束
│
├── shared/                             ← 内部共享协议
│   ├── audit_discipline.md             ← 审计纪律
│   ├── coverage_policy.md              ← 覆盖率策略（含 10 维度）
│   ├── phase_definitions.md            ← 阶段定义
│   ├── platform_dispatch.md            ← 跨平台调度策略（含模型路由）
│   ├── poc_policy.md                   ← PoC 安全与证据
│   ├── verification_principles.md      ← 验证原则
│   ├── report_fields.md                ← 报告字段定义
│   ├── dast_integration.md             ← DAST MCP 集成规范
│   ├── config/                         ← 配置文件
│   │   ├── model_routing.json          ← 模型路由配置（4 profile）
│   │   ├── tier_rules.json
│   │   ├── file_scope.json
│   │   └── priority_keywords.json
│   └── tools/                          ← 辅助脚本
│
├── scripts/                            ← 辅助脚本
├── docs/                               ← 项目文档
│   ├── tch-competition-research.md     ← TCH 赛事调研报告
│   └── architecture-design.md          ← 本文档
│
└── README.md
```

---

## 三、执行流程

```
用户: "开始审计"
    │
    ▼
[audit-orchestrator] 平台检测 + 模型路由初始化
    ├── CC → Agent 工具调度 + model_routing.json 路由
    ├── Cursor → Task(generalPurpose) 调度
    └── 降级 → 自身顺序执行
    │
    ▼
Phase 0: 度量 + 反编译    ← orchestrator 直接执行
    │
    ▼
Phase 1: 侦察              ← audit-recon-agent (model_tier: fast)
    │
    ▼
Phase 2: 双轨并行审计       ← audit-sink-agent ∥ audit-control-agent (model_tier: high)
    │                          同时输出 primitives
    │                          内部 FSM: SEARCH→LOCATE→TRACE→EVALUATE→RECORD
    │
    ▼
Phase 2.5: 独立监督检查     ← audit-advisor-agent (model_tier: balanced)
    │                          覆盖均衡性/发现质量/方向偏移/技术栈核查
    │
    ▼
Phase 3: 覆盖率校验 + 质量评估  ← orchestrator
    │  < 100% → 回到 Phase 2（应用 advisor 建议）
    │  = 100% ↓
    ▼
Phase 4+5: 并行             ← audit-validate-agent (model_tier: max) ∥ audit-composer-agent (high)
    │                          validate 可选触发 DAST 动态验证
    ▼
Phase 6: 报告生成           ← audit-report-agent (model_tier: fast)
    │
    ▼
Phase 7（可选）: 知识沉淀    ← audit-knowledge-learn skill
    │                          V2+ 漏洞模式 → learned/ 目录
    ▼
输出: audit/security_audit_report.md
```

---

## 四、组件间数据流

```
Phase 0 → metrics.md
              │
Phase 1 → in_scope_files.txt
         → endpoint_list.md
         → sink_list.md
         → auth_model.md
         → dependency_list.json
              │
Phase 2 → findings_batch{N}.md      → Phase 4 验证
         → primitives_batch{N}.md   → Phase 5 组合
         → reviewed_paths_batch{N}.txt → Phase 3 覆盖率
              │
Phase 2.5 → advisor_report.md       → orchestrator 纠偏
              │
Phase 3 → false_positive_notes.md   → Phase 4 参考
         → coverage_status.json     → 含 quality_metrics
              │
Phase 4 → validated_findings.md     → Phase 6 报告
         → (可选) dast_results.json → 升级 V1→V3
Phase 5 → composite_findings.md     → Phase 6 报告
         → primitive_chains.md      → Phase 6 报告
              │
Phase 6 → security_audit_report.md  ← 唯一交付物
              │
Phase 7 → knowledge_learn_report.md
         → learned/*.md             ← 自学习知识沉淀
```

---

## 五、双平台适配策略

### Cursor 模式

| 组件 | Cursor 行为 |
|------|-------------|
| Skills | 自动从 skills/ 发现，Agent Decides 模式 |
| Agents | 自动从 agents/ 发现，作为 Agent 配置 |
| Rules | 自动从 rules/ 发现，按 globs 匹配激活 |
| shared/ | 不自动发现，由 skill/agent 主动 Read |
| 调度 | Task(subagent_type="generalPurpose") |
| 模型路由 | 忽略（inherit），model_tier 仅文档性 |

### Claude Code 模式

| 组件 | CC 行为 |
|------|---------|
| Skills | 从 skills/ 读取 SKILL.md |
| Agents | 从 agents/ 读取 .md 文件 |
| Rules | 不适用（CC 无 .mdc 支持） |
| shared/ | 由 skill/agent 主动 Read |
| 调度 | Agent(name="agent-name", model=...) |
| 模型路由 | 读取 model_routing.json，按 tier→model 映射 |

---

## 六、质量保障机制

### 四层防线

```
第一层：Rules（自动激活）
├── audit-quality.mdc    → 反幻觉铁律（audit/ 下自动激活）
├── audit-workflow.mdc   → 工作流约束（审计关键词触发）
└── audit-report.mdc     → 报告格式约束（audit/*.md 时激活）

第二层：Skills（Agent 判断）
├── 降噪规则 → 只报有实际危害的漏洞
├── 覆盖率策略 → 三层覆盖率 + OWASP 域一致性检查
├── FSM 循环 → SEARCH→LOCATE→TRACE→EVALUATE→RECORD 禁止跳步
└── 验证等级 → V0-V4 分级

第三层：Advisor（独立监督）
├── 维度覆盖均衡性检查
├── 发现质量评估（A/B/C/D）
├── 审计方向偏移检测
├── 技术栈特有风险核查
└── OWASP Top 10 一致性检查

第四层：Orchestrator（编排保障）
├── 产出验证 → 每阶段检查文件完整性
├── 质量评估 → 降噪率/证据完整率/覆盖增长/维度均衡性
├── 失败恢复 → 重试→部分恢复→降级→阻塞通知
└── 进度精确 → 禁止估算，精确覆盖率
```

### 反幻觉 5+1 铁律

1. 报告漏洞前必须 Glob/Read 验证文件存在
2. 代码片段必须来自 Read 输出
3. 调用链每跳标注文件:行号
4. 不确定标「待验证」不标「已确认」
5. 不确定 ≠ 丢弃
6. 禁止虚报目录不存在

---

## 七、TCH 赛事借鉴实施状态

| 借鉴项 | 来源队伍 | 优先级 | 状态 |
|--------|----------|--------|------|
| 独立监督 Agent | #5 奇盾 | P1 | ✅ 已实现（audit-advisor-agent） |
| FSM 状态机审计循环 | #7 ChainReactors | P0 | ✅ 已实现（sink/control SKILL.md） |
| 模型异构路由 | #6 大可, #7 ChainReactors | P2 | ✅ 已实现（model_routing.json 4 profile） |
| 知识库版本管理 | — | P0 | ✅ 已实现（YAML 头 last_updated） |
| 评估循环 | #7 ChainReactors | P1 | ✅ 已实现（Phase 3 质量评估 5 指标） |
| 自学习知识沉淀 | #1 绿盟, #5 奇盾 | P2 | ✅ 已实现（knowledge-learn skill + learned/） |
| DAST 动态扫描集成 | #9 星空有云 | P2 | ✅ 规范已定义（dast_integration.md），实现待开发 |
| 知识库 RAG 索引化 | #5 奇盾, #6 大可 | P2 | ⬜ 未实现（静态文件，未索引化） |

---

## 八、模型路由配置

4 个预定义 profile，运行时可通过 `audit/state.json` 的 `model_profile` 字段切换：

| Profile | fast | balanced | high | max | 适用场景 |
|---------|------|----------|------|-----|---------|
| default | sonnet | sonnet | sonnet | opus | 日常审计 |
| high_accuracy | sonnet | sonnet | opus | opus | 关键项目 |
| cost_optimized | haiku | haiku | sonnet | sonnet | 大项目控成本 |
| multi_vendor | haiku | sonnet | sonnet | opus | 多模型互补 |

---

## 九、发布路径

```
1. 本地测试
   ln -s /path/to/cursor_plugin ~/.cursor/plugins/local/code-security-audit

2. 验证
   - Rules 在 audit/ 下编辑时自动激活
   - Skills 在聊天中可通过 /code-security-audit 触发
   - Agents 在 Agent 选择器中可见
   - Advisor 在 Phase 2 后自动调度

3. 发布
   → cursor.com/marketplace/publish 提交
```
