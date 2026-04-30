# TCH 智能渗透挑战赛调研分析报告

## 一、赛事概况

TCH 智能渗透挑战赛是国内顶级的 AI 驱动安全攻防比赛，参赛队伍使用 AI Agent 系统自主完成渗透测试任务。本文分析前 10 名队伍的技术方案，提取对 code-security-audit 插件的可借鉴设计。

---

## 二、各队伍技术方案分析

### 第1名：AI 小分队（绿盟）

**核心设计理念（4 条原则）**：
1. **智能决策要有工程边界**：AI 的自主空间需要框架约束
2. **执行环境必须隔离可重置**：每次渗透任务独立隔离
3. **经验要沉淀成共享状态**：渗透经验持久化为知识
4. **架构要做"稳定骨架"，不要做"能力枷锁"**：框架不限制 AI 能力

**对 code-security-audit 的启示**：
- 当前 SKILL.md 的 MUST/SHOULD/MAY 分层正是"工程边界"的体现
- `audit/state.json` 的状态持久化对应"经验沉淀"
- 但"能力枷锁"警告值得注意——过多的硬约束可能限制 AI 的自主发现能力

---

### 第2名：Sniper（天翼安全）

**关键概念**：
- **核心原理 vs 擅长场景 vs 决策能力 vs 攻击深度**的对比分析框架
- 强调"推高上限"和"拓展边界"

**对 code-security-audit 的启示**：
- 当前系统重视"降噪"（降低下限误报），但较少关注"推高上限"（发现更深层漏洞）
- 可考虑增加"深度攻击模式"：对 Phase 4 验证通过的漏洞尝试更深层利用链

---

### 第3名：Bytex（个人）

**方案**：图片型 PDF，文本提取有限。从 41 页的篇幅看是详细的技术方案。

---

### 第4名：ToBeNumberOne（京东）

**核心理念**：
- **Less Structure, More Intelligence**：减少结构化约束，增强智能推理
- **Less Tech, More Business**：从业务视角而非技术视角审计
- 工具以 `tools/<name>/` 目录组织
- Web 应用爬取和地图构建（Login→Dashboard→Categories→Products→Users）

**对 code-security-audit 的启示**：
- 当前 endpoint_list.md 的格式可以增加业务语义标注
- "Less Structure" 理念提示：Phase 2 的双轨审计可以给 AI 更多自主判断空间

---

### 第5名：奇盾明焰战队（最具参考价值）

**架构设计（多 Agent 协同）**：

```
MAIN（主会话）
├── ADVISOR AGENT          ← 独立上下文，宏观纠偏
│   ├── 读取 .pentest-notes.md
│   ├── 分析主会话日志
│   └── 生成优先级建议（ALLOW/BLOCK）
├── ALIGNMENT AGENT        ← 意图对齐检查
│   └── 检查是否是长时间任务
├── KB ANALYST AGENT       ← 知识库分析
│   ├── 双知识库 RAG 检索
│   │   ├── 公开 Writeup 知识库
│   │   └── 自学习知识库
│   └── Bash + RAG 双路检索
└── 笔记 Agent             ← 共享记忆管理
    └── .pentest-notes.md（Target Info + TODO + COMPLETED）
```

**关键创新**：
1. **Harness Engineering**：通过 Harness 设计持续约束和校准 Agentic Loop，而非单纯依赖 Prompt
2. **Advisor Agent 纠偏**：独立上下文的宏观监督，摆脱单一 Agentic Loop 的注意力陷阱
3. **KB Analyst Agent**：知识库分析 Agent 在渗透陷入死胡同时注入外部知识（如 PEARCMD 利用链）
4. **上下文压缩**：Compact Instructions 处理长会话

**实战案例**：
- CSRF + 存储型 XSS 链：Advisor 在主会话发散时明确战略方向
- LFI-to-RCE：KB Analyst 从知识库找到 PEARCMD URL 构造方法

**对 code-security-audit 的启示**：
- **当前缺失**：没有类似 Advisor Agent 的独立宏观监督机制
- **可借鉴**：在 orchestrator 中增加"审计顾问"功能，在 Phase 2 分批审计时检查是否遗漏重要维度
- **知识库**：当前 `resources/knowledge/` 是静态文件，可以增加 RAG 检索能力

---

### 第6名：运行完成（中国电信大可实验室）

**技术要点**：
1. **专项 Skills 维护、知识库沉淀**
2. **断点续跑、模型无关、资源可控**
3. **精细化记忆压缩与检索机制**
4. **模型异构路由**：按 Agent 角色分配不同模型，在成本和效果之间寻找帕累托前沿
5. **人机精准协同**

**对 code-security-audit 的启示**：
- **模型路由**：当前所有 Agent 使用 `model: inherit`，可以为不同阶段分配不同模型（如 Phase 1 侦察用快速模型，Phase 4 验证用高精度模型）
- **记忆压缩**：当前的上下文管理策略可以进一步优化

---

### 第7名：For Future（ChainReactors / Chainreactor + M09ic）（极具参考价值）

**核心数据**：
- Day 1 纯 Claude Code：排名 #42
- Day 2 加入工程框架（同模型、同 prompt、同战队）：排名 #4
- **唯一变量 = 工程**，证明工程化是 AI 安全能力的放大器

**三层架构**：

```
INTENT（意图层）
├── 人类意图：Intent（动态）+ Task（TASK.md 静态）
├── 评估介入：HITL/AI Evaluate
└── 会话隔离

PATTERN（FSM 执行引擎）
├── INTENTION → 理解目标，初始化上下文
├── ACTION    → 执行尝试，调用 Executor
├── EVALUATION → 判断结果，retry/pass
└── RESULT    → 目标满足，输出结果

EXECUTOR（Agent 后端）
├── claude-code (haiku/opus)
├── codex (gpt-5.4)
└── opencode (pydantic-ai)

WORKSPACE（工作环境层）
├── Layout: .aide/ + resources/
├── Memory: markdown 持久化
├── Skills: SKILL.md（纯自然语言）
├── Tools: task + memory
├── Knowledge: nuclei templates
├── MCP Server: HTTP MCP 动态注册
└── Task Pool: 多任务调度
```

**关键创新**：
1. **FSM 状态机驱动**：INTENTION→ACTION→EVALUATION→RESULT 循环
2. **Engineering = Information × Feedback**（控制论视角）
3. **Prompt Engineering → Context Engineering → Harness/Environment Engineering** 演变脉络
4. **外层调度器（Claude Code /loop 5m）+ 内层解题器（aide 容器）**分离
5. **"构造 Agent 的 Agent"**：宿主层用 AI 做调度决策

**对 code-security-audit 的启示**：
- **FSM 模式**：当前 Phase 0→6 是线性流程，可以在 Phase 2 内部引入 FSM（搜索→定位→追踪→验证→记录）
- **Evaluation 循环**：当前缺少 Phase 2 执行质量的自动评估
- **多 Executor 后端**：当前只考虑了单一 LLM 后端，可以扩展为多模型路由

---

### 第9名：星空有云（个人）

**多层调度架构**：

```
Dispatcher
├── Lead (Web)   → op-recon, op-attack×2, Monitor
├── Lead (CVE)   → op-recon, op-attack×2, Monitor
├── Lead (Network) → op-recon, op-attack×2, Monitor
└── Lead (AD)    → op-recon, op-attack×2, Monitor

Agent 调度系统
├── dispatch / recon / vuln test / Threat model / recovery / monitor
├── SubAgent: claude + codex + oh-my-pi
└── A2A (Agent-to-Agent) 通信

DAST 平台
├── mitm-proxy
├── Dast-server / Dast-worker
├── 反连平台
└── Agent Browser
```

**关键流程（6步侦察）**：
1. 端口扫描 → 通知 Lead
2. Web 资产发现 → 通知 Lead
3. 指纹 + CVE 库 → DSL 引擎检测
4. 增量接口 → 中间人流量打入 DAST / BFS 穷举
5. 敏感目录 → 通知 Lead
6. 回顾总结 → 侦查完成

**对 code-security-audit 的启示**：
- **Lead/Operator 分层**：类似于当前的 orchestrator/agent 分层，但更细粒度
- **DAST 集成**：当前是纯静态分析，可考虑集成动态扫描能力
- **漏洞优先级排序**：按"更难"分级处理

---

## 三、共性趋势总结

| 趋势 | 出现队伍 | 对 code-security-audit 的映射 |
|------|----------|-------------------------------|
| 多 Agent 协同 | 1,5,6,7,9 | 已实现（orchestrator + 6 agents） |
| FSM/状态机驱动 | 7 | 未实现，可在 Phase 2 引入 |
| 独立监督/纠偏 Agent | 5 | 未实现，建议增加 audit-advisor |
| 知识库 RAG | 5,6 | 部分实现（静态 knowledge/），可增强 |
| 模型异构路由 | 6,7,9 | 未实现，当前 `model: inherit` |
| 断点续跑/状态持久化 | 1,6 | 已实现（state.json） |
| 执行环境隔离 | 1,7 | 部分实现（每个 Agent 独立上下文） |
| 经验沉淀 | 1,5,6 | 部分实现（knowledge/），可增强 |
| 工程 > Prompt | 7 | 核心理念一致 |
| 人机协同 | 6,9 | 已实现（继续审计机制） |

---

## 四、可落地优化建议（按优先级）

### P0：立即可做

1. **模型路由声明**：在 agent YAML 中支持 `model` 建议（如 Phase 1 用 fast 模型，Phase 4 用 high 模型），Cursor 可忽略、CC 可使用
2. **Phase 2 内部 FSM**：在 audit-sink/control SKILL.md 中引入搜索→定位→追踪→验证→记录的循环模式
3. **知识库版本标记**：给每个 knowledge/*.md 加 `last_updated` 字段

### P1：中期优化

4. **audit-advisor Agent**：独立于 Phase 2 执行的监督 Agent，定期检查审计方向是否偏移、是否遗漏关键域
5. **评估循环**：Phase 2 每批结束后自动评估发现质量（降噪率、覆盖率增长、高风险域命中率）
6. **知识库 RAG 增强**：将 knowledge/ 文件索引化，Phase 4 验证时按漏洞类型自动检索

### P2：长期演进

7. **多模型 Executor**：支持在不同阶段使用不同 LLM（如 Claude 做深度分析、Codex 做代码搜索）
8. **动态扫描集成**：增加 MCP server 对接 DAST 工具
9. **自学习知识库**：将审计中验证通过的漏洞模式自动沉淀为新的 knowledge 文件
