# LLM 白盒代码审计工程架构设计

本文定义 `code-security-audit` 的工程化架构。核心目标是把 LLM 从“单轮问答式找洞”约束为可追溯、可验证、可复盘的白盒审计流水线。

## 1. 总体流水线

```mermaid
flowchart TB
  U["用户授权范围与源码"] --> P0["阶段 0<br/>范围、度量、反编译预处理"]
  P0 --> P1["阶段 1<br/>项目画像与攻击面侦察"]
  P1 --> INV["project_inventory.json<br/>语言/框架/依赖/服务/数据存储"]
  P1 --> ARCH["architecture_inventory.md<br/>模块/数据流/信任边界"]
  P1 --> AUTH["auth_model.md<br/>认证/授权/租户/拦截链"]
  P1 --> COV["owasp_coverage_matrix.md<br/>ASVS/WSTG/Top10/CWE"]
  P1 --> P2["阶段 2<br/>Sink-driven + Control-driven 审计"]
  BASE["SAST/SCA/Secret/依赖版本基线"] --> P2
  P2 --> CAND["candidate_findings.json<br/>候选 finding + V0/V1"]
  CAND --> P3["阶段 3<br/>覆盖率校验与 finding-skeptic"]
  P3 --> FP["false_positive_notes.md<br/>误报与排除理由"]
  P3 --> P4["阶段 4<br/>PoC/测试验证与评分"]
  ENV{"用户提供测试环境?"} -->|是| V4["V4 端到端验证"]
  ENV -->|否| V2["V2/V3 最小单元或集成测试"]
  V4 --> P4
  V2 --> P4
  P4 --> VAL["validation_results.json<br/>V0-V4、命令、结果、限制"]
  P4 --> POC["audit/poc/<finding-id>/<br/>PoC、测试、清理步骤"]
  VAL --> P5["阶段 5<br/>组合漏洞与攻击链"]
  P5 --> CHAIN["composite_findings.md"]
  CHAIN --> P6["阶段 6<br/>最终报告"]
  VAL --> P6
  COV --> P6
  ARCH --> P6
  P6 --> REPORT["security_audit_report.md"]
```

## 2. Skill 模块架构

```mermaid
flowchart LR
  CTRL["code-security-audit<br/>总控协议"] --> RECON["audit-recon<br/>项目画像"]
  CTRL --> SINK["audit-sink<br/>source-to-sink"]
  CTRL --> CONTROL["audit-control<br/>auth/authz/业务控制"]
  CTRL --> VALIDATE["audit-validate<br/>验证与评分"]
  CTRL --> REPORT["audit-report<br/>唯一交付报告"]

  RECON --> A1["入口、sink、依赖、鉴权模型"]
  SINK --> A2["注入、SSRF、反序列化、文件、模板、表达式"]
  CONTROL --> A3["未授权、越权、IDOR/BOLA、多租户、状态机"]
  VALIDATE --> A4["V0-V4、PoC、单测/集成/E2E、CVSS"]
  REPORT --> A5["报告、覆盖矩阵、残余风险、修复计划"]
```

## 3. 数据产物架构

```mermaid
flowchart TB
  subgraph Phase0["audit/phase0"]
    M["metrics.md"]
    S["scope.md"]
  end
  subgraph Phase1["audit/phase1"]
    INV["project_inventory.json"]
    ARCH["architecture_inventory.md"]
    AUTH["auth_model.md"]
    DEP["dependency_list.json"]
    EP["endpoint_list.md"]
    SK["sink_list.md"]
    FILES["in_scope_files.txt"]
    COV["owasp_coverage_matrix.md"]
  end
  subgraph Phase2["audit/phase2"]
    BATCH["findings_batch{N}.md"]
    REVIEW["reviewed_paths_batch{N}.txt"]
    CAND["candidate_findings.json"]
    CALL["callchain_tracker.md"]
  end
  subgraph Phase3["audit/phase3"]
    STATUS["coverage_status.json"]
    FP["false_positive_notes.md"]
  end
  subgraph Phase4["audit/phase4"]
    VF["validated_findings.md"]
    VR["validation_results.json"]
    RJ["rejected_findings.md"]
  end
  subgraph POC["audit/poc"]
    TESTS["finding-id/reproduce.* 或 test_*"]
  end
  subgraph Phase5["audit/phase5"]
    COMBO["composite_findings.md"]
  end
  subgraph Final["最终交付"]
    REPORT["security_audit_report.md"]
  end

  Phase0 --> Phase1 --> Phase2 --> Phase3 --> Phase4 --> POC --> Phase5 --> Final
  Phase4 --> Final
```

## 4. 工程原则

| 原则 | 设计含义 |
|------|----------|
| LLM 是编排器，不是唯一裁决器 | LLM 负责语义理解、跨文件追踪、报告组织；最终 finding 必须有代码证据和验证等级 |
| 画像先于找洞 | 不先明确语言、框架、鉴权、依赖、入口、数据存储，就无法判断漏洞是否可达 |
| 标准覆盖先于结果数量 | 用 OWASP ASVS/WSTG/Top 10/CWE 建立覆盖矩阵，避免只输出模型容易想到的漏洞 |
| 候选与漏洞分离 | 阶段 2 产出 candidate，阶段 4 验证后才可进入 final report |
| 反向审查必须存在 | finding-skeptic 检查全局鉴权、框架默认保护、ORM 参数化、schema validation 和不可达代码 |
| 测试环境优先 | 用户提供测试环境时做 V4；没有测试环境时用最小化单元/集成测试做 V2/V3 |
| 唯一交付报告 | 最终报告必须内联关键证据、复现细节和修复建议，不能要求读者跳转中间文件理解漏洞 |

## 5. 与传统 SAST 的分工

| 能力 | SAST/SCA/Secret 工具 | LLM 白盒审计 |
|------|----------------------|--------------|
| 依赖漏洞 | 强 | 用于确认版本、影响路径和修复建议 |
| 简单 sink 模式 | 强 | 用于过滤误报、追踪业务上下文 |
| 跨文件业务逻辑 | 弱到中 | 强，但必须验证 |
| 鉴权/越权/租户隔离 | 弱到中 | 强，尤其适合读拦截器、权限表、资源归属 |
| PoC/测试生成 | 弱 | 强，但必须在授权环境中执行 |
| 可审计报告 | 中 | 强，适合整合证据、标准映射和残余风险 |

结论：最佳工程形态不是“LLM 替代 SAST”，而是 **SAST/SCA/Secret 生成基线 + LLM 做项目级语义审计 + 测试验证收敛误报**。
