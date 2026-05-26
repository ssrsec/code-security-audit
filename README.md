# code-security-audit

AI 驱动的代码安全审计框架。支持 redteam/full 两种模式，支持靶场集成验证，采用 Orchestrator + Agent Team 架构全程自动编排。适配 Cursor、Claude Code 及其他支持 Agent 调度的 AI IDE。

## 核心特性

- **双模式审计**：redteam（围绕攻防演练得分点，按五个维度组织审计）/ full（含业务逻辑漏洞）
- **靶场集成验证**：提供靶场地址后自动构造真实请求深度验证漏洞，而非浅层端点可达性检查
- **通用系统识别**：自动识别已知系统（RuoYi/Jenkins/WordPress 等）并搜索历史漏洞情报
- **全量覆盖**：禁止抽样，100% 逐文件审阅，三层覆盖率分别记录
- **双轨组合分析**：漏洞×漏洞 + 原语×原语 两条独立推导路径
- **反幻觉**：代码证据为王，所有路径/代码片段必须来自实际 Read/Glob 输出
- **用户求助机制**：遇到无法自动解决的问题（登录失败/靶场异常/跨平台工具等）主动向用户求助，不自行跳过
- **授权声明注入**：关键执行节点注入企业授权声明，防止 AI 拒绝输出安全测试内容

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

### redteam 模式

围绕攻防演练得分点，按五个维度组织：

| 维度 | 典型漏洞 |
|------|---------|
| **应用权限获取** | 弱口令、登录绕过、鉴权绕过、越权、验证码绕过、SSO/OAuth 缺陷 |
| **主机权限获取** | 命令注入、代码执行、反序列化 RCE、文件上传 getshell、SSTI |
| **数据库权限获取** | SQL 注入、获取数据库连接信息后连接执行 |
| **数据获取** | 未授权访问、任意文件读取/下载、敏感信息泄露 |
| **高危可组合漏洞** | SSRF、路径穿越、硬编码凭据等 |

红队模式排除需要用户交互的漏洞（CSRF、反射型/DOM 型 XSS），但存储型 XSS 能直接获取管理员权限的除外。灵活判定：同一漏洞类型按实际危害归类（如文件上传竞态→getshell 属红队，优惠券竞态属全量）。

### full 模式

包含 redteam 全部内容 + 纯业务逻辑漏洞（支付篡改、状态机跳跃、库存绕过、Mass Assignment 等）。

## 审计流程

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6
参数解析   侦察     双轨审计   质量门     验证       组合分析   报告
+度量     +系统识别 (Sink‖    +覆盖率    +靶场验证  (漏洞组合   +质量检查
+反编译   +情报收集  Control) +去重      +深度利用  ‖原语组合)
                            +跨批次
                             数据流匹配
```

| 阶段 | 名称 | 说明 |
|------|------|------|
| Phase 0 | 度量与预处理 | 解析审计参数、统计项目度量、反编译二进制产物 |
| Phase 1 | 项目侦察 | 技术栈识别、端点枚举、Sink 列表、认证模型、已知系统历史漏洞情报 |
| Phase 2 | 双轨全量审计 | Sink-driven（数据流追踪）+ Control-driven（控制缺失检查）并行，同时发射原语 |
| Phase 3 | 质量门 | 覆盖率校验、候选去重、OWASP Top 10 完整性检查、跨批次数据流匹配 |
| Phase 4 | 验证与评分 | 对每条候选做 V0-V4 验证、PoC 生成、CVSS 评分，有靶场时深度实际利用验证 |
| Phase 5 | 组合分析 | 漏洞×漏洞组合攻击链推导 + 原语×原语跨能力组合推导（并行） |
| Phase 6 | 报告生成 | 严格五章节结构的最终报告，质量自检后交付 |

## Agent 架构

```
audit-orchestrator（总编排控制器）
    ├── audit-recon-agent       ← Phase 1 侦察 + 通用系统识别
    ├── audit-sink-agent        ← Phase 2 Sink-driven（与 control 并行）
    │    └── primitives_batch    （同时发射原语）
    ├── audit-control-agent     ← Phase 2 Control-driven（与 sink 并行）
    │    └── primitives_batch    （同时发射原语）
    ├── audit-validate-agent    ← Phase 4 单漏洞验证 + 靶场深度验证
    ├── audit-composite-agent   ← Phase 5 漏洞组合（与 primchain 并行）
    ├── audit-primchain-agent   ← Phase 5 原语组合（与 composite 并行）
    └── audit-report-agent      ← Phase 6 报告生成
```

平台适配：Cursor 用 Task 工具、Claude Code 用 Agent 工具调度子 Agent，其他平台降级为顺序执行。

## 报告输出

| 条件 | 输出形式 |
|------|---------|
| 漏洞总数 ≤ 20 | 单文件 `audit/security_audit_report.md` |
| 漏洞总数 > 20 | 主报告 + 每条漏洞独立文件 `audit/findings/vul-NNN.md` |

报告严格五章节：一、项目代码审计总结 → 二、漏洞汇总表 → 三、漏洞详情 → 四、组合漏洞摘要 → 五、总体安全建议。

每条漏洞包含：元信息表格（含完整 CVSS 3.1 向量）、Burp 风格复现步骤、实战利用场景、修复建议（含业务影响评估）。

## 集成工具

项目内置安全测试辅助工具，用于 Phase 4 靶场验证阶段：

| 工具 | 路径 | 说明 |
|------|------|------|
| **javachains** | `scripts/tools/javachains/` | Java 反序列化利用链生成器（[vulhub/java-chains](https://github.com/vulhub/java-chains)）。`cli-chains.jar` 超过 GitHub 100MB 限制未纳入仓库，需自行从 [Releases](https://github.com/vulhub/java-chains/releases) 下载放置，见 [说明](scripts/tools/javachains/README.md) |
| **ysoserial.net** | `scripts/tools/yso-net/` | .NET 反序列化 payload 生成器（目标 .NET Framework 4.x，需 Windows 运行） |
| **ysoserial.net (fw2)** | `scripts/tools/yso-net-v2/` | .NET 反序列化 payload 生成器（目标 .NET Framework 2.0，需 Windows 运行） |
| **payload 模板** | `scripts/tools/payload_templates/` | 9 个漏洞类型的 payload 知识库 + 常见框架快速验证模板（RuoYi/Spring Boot/MyBatis/.NET） |

详细用法见 `scripts/tools/exploit_tools.md`。

> 当前环境无法运行的工具（如 macOS 上的 ysoserial.net），AI 会向用户求助并提供完整命令，由用户在对应环境执行后返回结果。

## 安装

### Cursor

将本仓库 clone 到项目根的 `.cursor/skills/code-security-audit/` 下：

```bash
mkdir -p .cursor/skills
git clone https://github.com/ssrsec/code-security-audit.git .cursor/skills/code-security-audit
```

orchestrator 会自动检测平台并使用 Task 工具调度子 Agent。`rules/` 下的约束规则会在 Cursor 中按 globs 自动激活。

### Claude Code

```bash
claude --plugin-dir /path/to/code-security-audit
```

`agents/*.md` 会被自动注册为可调度的子 Agent。

### 其他 AI IDE

只要 AI 能读取文件和执行命令，orchestrator 会降级为顺序执行模式，直接读取 `skills/*/SKILL.md` 按步骤执行。

### 首次使用前

1. 从 [java-chains Releases](https://github.com/vulhub/java-chains/releases) 下载 CLI 版本的 JAR，放到 `scripts/tools/javachains/cli-chains.jar`
2. 确保 Java 运行时已安装（`java -version`）
3. 如需验证 .NET 反序列化漏洞，确保有 Windows 环境可运行 ysoserial.net

## 目录结构

```
code-security-audit/
├── SKILL.md                            # 总控协议（审计模式/报告策略/核心原则/授权声明）
├── agents/                             # Agent 接口文件（触发条件+输入输出+指向 SKILL）
│   ├── audit-orchestrator.md           # 总编排控制器（Phase 0-6 全流程调度）
│   ├── audit-recon-agent.md            # Phase 1 侦察
│   ├── audit-sink-agent.md             # Phase 2 Sink-driven 数据流审计
│   ├── audit-control-agent.md          # Phase 2 Control-driven 控制缺失检查
│   ├── audit-validate-agent.md         # Phase 4 验证（含靶场深度验证/用户求助）
│   ├── audit-composite-agent.md        # Phase 5 漏洞组合攻击链推导
│   ├── audit-primchain-agent.md        # Phase 5 原语组合攻击链推导
│   └── audit-report-agent.md           # Phase 6 报告生成
├── skills/                             # 各阶段详细规则（行为定义的单一事实来源）
│   ├── audit-recon/SKILL.md            # 项目侦察 + 通用系统识别
│   ├── audit-sink/SKILL.md             # Sink-driven 数据流追踪
│   ├── audit-control/SKILL.md          # Control-driven 认证/授权检查
│   ├── audit-primitives/SKILL.md       # 安全原语识别格式
│   ├── audit-validate/SKILL.md         # V0-V4 验证 + 靶场深度验证 + 工具集成
│   │   └── resources/knowledge/        # 漏洞类型知识库（20+ 条件判定文档）
│   ├── audit-composite/SKILL.md        # 漏洞×漏洞组合分析
│   └── audit-report/SKILL.md           # 报告生成规则
│       └── resources/report_template.md
├── shared/                             # 跨阶段共享协议（按需读取，非一次性加载）
│   ├── phase_definitions.md            # 各阶段动作/输入/输出/门禁定义
│   ├── audit_discipline.md             # 审计范围 + 反幻觉铁律
│   ├── report_fields.md                # 报告字段/章节/准入标准（单一事实来源）
│   ├── verification_principles.md      # V0-V4 验证等级定义
│   ├── poc_policy.md                   # PoC 安全边界 + 证据完整性
│   ├── coverage_policy.md              # 覆盖率策略
│   ├── taint_propagation.md            # 污点传播 + 伪 sanitizer 识别
│   ├── sink_reachability_checklist.md  # R1-R7 可达性验证算法
│   ├── sink_catalog_by_lang.md         # 各语言危险 Sink API 速查
│   ├── framework_catalog.md            # 框架/鉴权绕过速查
│   ├── decompilation.md                # 反编译三级降级策略
│   ├── external_knowledge_protocol.md  # 联网搜索协议
│   ├── secret_detection.md             # 硬编码凭据/密钥检测规则
│   ├── composite_vulnerability_analysis.md
│   ├── primitive_chain_catalog.md
│   └── ...
├── scripts/
│   ├── quality_check.py                # 报告质量自检（Phase 4/6 自动调用）
│   └── tools/
│       ├── exploit_tools.md            # 工具使用文档（完整用法/示例/选择指南）
│       ├── javachains/                 # Java 反序列化工具（需下载 JAR，见 README）
│       │   ├── README.md
│       │   └── chains-config/          # 第三方 gadget 依赖库（已随仓库提供）
│       ├── yso-net/                    # ysoserial.net（.NET Framework 4.x）
│       ├── yso-net-v2/                 # ysoserial.net（.NET Framework 2.0）
│       └── payload_templates/          # payload 知识库
│           ├── java_deser_chains.md    # Java 反序列化链
│           ├── fastjson_payloads.md    # Fastjson payload
│           ├── sqli_by_dialect.md      # SQL 注入（按数据库方言）
│           ├── ssti_by_engine.md       # 模板注入
│           ├── ssrf_bypass.md          # SSRF 绕过
│           ├── dotnet_deser_chains.md  # .NET 反序列化链
│           ├── ...
│           └── quick_verify/           # 常见框架快速验证模板
│               └── common_frameworks.md
└── rules/                              # 审计约束规则（Cursor 中按 globs 自动激活，其他平台作为参考文档）
    ├── audit-workflow.mdc              # 工作流约束（Phase 严格顺序/禁止跳步/进度格式）
    ├── audit-report.mdc               # 报告格式约束（五章节/CVSS/零容忍占位符）
    └── audit-quality.mdc              # 反幻觉约束（证据验证/待验证不丢弃）
```
