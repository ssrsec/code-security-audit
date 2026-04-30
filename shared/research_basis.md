# 研究依据与落地项目基线

本文汇总 `code-security-audit` 采用的论文、标准、数据集和 GitHub 落地项目。它们共同支持一个结论：LLM 可以提升白盒审计效率，但必须被约束在“项目画像、标准覆盖、验证分级、证据报告”的工程流程中。

## 1. 标准与官方资料

| 资料 | 在本 skill 中的用途 |
|------|--------------------|
| OWASP ASVS | 建立白盒安全需求覆盖矩阵，尤其是认证、会话、访问控制、输入验证、密码学、业务逻辑 |
| OWASP WSTG | 指导验证步骤、测试用例和端到端 PoC |
| OWASP Code Review Guide | 支撑“源代码审查不可被黑盒扫描完全替代”的方法论 |
| OWASP Top 10 | 用于管理层风险归类和报告摘要 |
| MITRE CWE | 用于 finding 根因分类、漏洞类型统计和修复模式索引 |
| FIRST CVSS | 用于漏洞严重性评分，要求输出向量和理由 |
| NIST SSDF SP 800-218 | 用于把发现映射到安全开发、修复、根因分析和流程改进 |
| NVD/CVE | 用于依赖漏洞版本、影响范围和公开修复证据 |

## 2. 论文与研究资料

| # | 论文/资料 | 方向 | 对本 skill 的设计约束 |
|---|-----------|------|----------------------|
| 1 | RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing | 仓库级 LLM 审计 | 需要 agent memory、按需探索、数据流事实、validator 和路径条件验证 |
| 2 | LLM-based Vulnerability Detection at Project Scale: An Empirical Study | 项目级实证评估 | 项目级 LLM 检测仍有误报、漏报、跨过程推理和成本问题，必须有覆盖矩阵和验证分级 |
| 3 | Vulnerability Detection with Code Language Models: How Far Are We? / PrimeVul | 真实漏洞检测基准 | 数据去重、标签质量、真实项目泛化是核心，不能把模型预测等同漏洞 |
| 4 | When Software Security Meets Large Language Models: A Survey | LLM 软件安全综述 | LLM 适合检测、测试、修复、triage，但需要工具链和人工复核 |
| 5 | Can Large Language Models Find And Fix Vulnerable Software? | 漏洞发现与修复 | LLM 有潜力，但修复和发现必须经过验证 |
| 6 | Exploring Prompt Patterns for Effective Vulnerability Repair in Real-World Code by Large Language Models | 真实代码修复 prompt | 需要控制流、上下文和分阶段 prompt；修复建议要可执行 |
| 7 | A Case Study of LLM for Automated Vulnerability Repair: Assessing Impact of Reasoning and Patch Validation Feedback | 验证反馈修复 | reasoning + 编译/测试/外部工具反馈可提升修复正确率 |
| 8 | Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via GNN | 图语义漏洞识别 | 漏洞识别依赖控制流、数据流和语义图，不能只看局部 token |
| 9 | LineVul: A Transformer-based Line-Level Vulnerability Prediction | 行级定位 | finding 应定位到文件:行号，但行级预测仍需可达性验证 |
| 10 | VulBERTa: Simplified Source Code Pre-Training for Vulnerability Detection | 代码预训练 | 预训练模型可做候选发现器，不可做最终裁决器 |
| 11 | DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection | 大规模漏洞数据集 | 大规模数据仍有泛化与类别难度问题，需要人工/工具验证 |
| 12 | Big-Vul: A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries | CVE/修复数据集 | 修复 commit 可用于漏洞模式、修复模式和回归测试模板 |
| 13 | CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software | CVE 到代码映射 | 可把 CVE、CWE、commit、文件、方法关联为证据链 |
| 14 | Large Language Model for Vulnerability Detection and Repair: Literature Review and the Road Ahead | 检测与修复综述 | 检测、修复、评测、人类反馈需要闭环设计 |
| 15 | A Systematic Literature Review on Detecting Software Vulnerabilities with Large Language Models | LLM 漏洞检测系统综述 | 需要持续更新评测方法、数据集和任务边界 |
| 16 | When LLMs meet cybersecurity: a systematic literature review | LLM 网络安全综述 | 安全任务覆盖广，但工具验证、攻击前提和误报控制是共性瓶颈 |

## 3. 数据集与评测资源

| 资源 | 可借鉴内容 | 使用边界 |
|------|------------|----------|
| PrimeVul | 真实漏洞检测基准、去重和数据泄漏控制 | 用于评测思路，不代表目标项目漏洞成立 |
| DiverseVul | 多语言、多 CWE 漏洞样例 | 用于知识库和模式索引，不直接作为证据 |
| Big-Vul | CVE、代码变更、漏洞摘要 | 适合修复模式和回归测试参考 |
| CVEfixes | CVE/CWE/commit/方法级关联 | 适合依赖版本和修复证据链 |
| SARD / Juliet | 人工构造漏洞样例 | 适合工具回归测试，不等价真实业务漏洞 |

## 4. GitHub 落地项目基线

| 项目 | 方向 | 可借鉴点 | 不足或边界 |
|------|------|----------|------------|
| `lintsinghua/DeepAudit` | 多智能体漏洞挖掘、PoC 验证、报告生成 | 发现-验证-报告闭环，多 agent 分工 | 需要补强标准覆盖、可追溯 schema 和企业报告规范 |
| `anthropics/claude-code-security-review` | 安全 PR Review GitHub Action | PR 集成、增量审查、自动化门禁 | 更偏 PR 变更审查，不替代全量白盒审计 |
| `The-PR-Agent/pr-agent` | AI PR 审查与改进建议 | 工程化集成、评审注释、diff 范围流程 | 安全深度和全量项目画像不足 |
| `PurCL/RepoAudit` | 仓库级 LLM agent 审计 | 按需探索、validator、仓库级上下文管理 | 学术原型需工程化产物和报告模板 |
| `duriantaco/skylos` | PR gate、安全流和 AI 代码回归 | 合并门禁和增量安全审查 | 不覆盖完整源代码白盒审计 |
| `codexstar69/bug-hunter` | Recon、skeptic、validator、fixer 分工 | 可借鉴角色拆分和反向审查 | 需加强验证等级和标准映射 |
| `jar-analyzer/jar-analyzer-claude` | JAR 产物审计和 sink 查询 | 对编译产物/Java 依赖审计有价值 | 技术栈偏 Java，不能覆盖所有语言 |
| `Armur-Ai/vibescan` | AI 生成代码安全扫描、SAST/DAST/沙箱 | 支持沙箱验证理念 | 更偏 AI 生成代码场景 |
| `MatterAIOrg/matter-ai` | AI reviewer + 测试生成 | 审计与测试生成组合 | 需补白盒项目画像和合规报告 |
| `momenbasel/vulnhawk` | AI SAST，关注 auth bypass/IDOR/logic bugs | 证明业务逻辑和越权是 LLM 审计重点 | 项目成熟度和覆盖面有限 |
| `allsmog/vuln-scout` | Claude Code 白盒渗透测试插件 | STRIDE/OWASP 与 whitebox skill 组合 | 需要工程化证据产物和验证闭环 |

## 5. 对本 skill 的结论

1. **架构画像是前置条件**：没有语言、框架、入口、鉴权、依赖、数据流和信任边界，finding 只能停留在猜测。
2. **LLM 输出必须被验证分级约束**：V0/V1 不是“已确认漏洞”；V2-V4 才能说明关键路径被测试或环境验证。
3. **标准覆盖比漏洞数量更重要**：报告必须说明 OWASP/ASVS/WSTG 覆盖情况，避免只列模型想到的高频洞。
4. **候选、误报、已验证、残余风险必须分离**：这是降低误报、保证合规和工程可复盘的关键。
5. **PoC 不是攻击炫技**：PoC 目标是证明漏洞成立和帮助修复验证，必须无害、可清理、可复现。

## 6. 本项目本地知识来源

本 skill 合并了当前项目中的以下 Markdown 资料：

| 文件 | 合并内容 |
|------|----------|
| `code-audit-projects.md` | GitHub AI 代码审计/安全审查项目调研、优势劣势和工程参考 |
| `llm-code-audit-workflow.md` | LLM 代码审计流程、rules/skills 约束、项目画像和验证闭环 |
| `llm-whitebox-code-audit-analysis.md` | 白盒审计观点、论文清单、OWASP 流程、V0-V4 验证分级、PoC/报告要求 |
| `code-security-audit/**/SKILL.md` | 原有阶段化审计 skill、反幻觉、覆盖率、验证和报告规则 |

合并时保留了原有“全量覆盖、反幻觉、组合漏洞、分阶段落盘”的优点，移除了与白盒工程化交付冲突的内容，例如只保留单一漏洞报告、不输出项目画像、强制删除所有过程证据等。
