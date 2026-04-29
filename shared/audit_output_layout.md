# 审计产出目录约定

## 目录结构

```
audit/
├── security_audit_report.md          # 唯一交付报告
├── state.json                         # 当前阶段、批次、覆盖率、finding 状态
├── phase0/
│   ├── metrics.md                    # 代码库度量（含审计开始时间、审计形态、反编译信息）
│   └── scope.md                      # 授权范围与审计范围
├── phase1/
│   ├── phase1_recon.md               # 技术栈、审计形态（简报）
│   ├── project_inventory.json        # 项目语言、框架、依赖、入口（结构化）
│   ├── architecture_inventory.md     # 模块结构、数据流、信任边界
│   ├── auth_model.md                 # 认证、授权、租户隔离模型
│   ├── framework_authz_map.md        # 框架级鉴权配置
│   ├── in_scope_files.txt            # 应审文件列表（覆盖率分母唯一来源）
│   ├── tier_list.json                # Tier 分类
│   ├── coverage_matrix.md            # 覆盖矩阵（OWASP/ASVS/WSTG/CWE）
│   ├── endpoint_list.md              # 端点清单
│   ├── sink_list.md                  # 危险 API 清单
│   ├── dependency_list.json          # 依赖清单
│   └── secret_inventory.md           # Secret 线索
├── phase2/
│   ├── findings_batch{N}.md          # 各批次候选漏洞
│   ├── reviewed_paths_batch{N}.txt   # 各批次审阅文件
│   ├── reviewed_paths_merged.txt     # 合并审阅清单
│   ├── candidate_findings.json       # 候选 finding 汇总
│   ├── coverage_status.json          # 覆盖率状态
│   ├── primitives_batch{N}.md        # 各批次原语能力片段
│   └── callchain_tracker.md          # 调用链追踪
├── phase3/
│   ├── false_positive_notes.md       # 反向审查与误报说明
│   ├── findings_verified.md          # 已验证漏洞（含「已确认」和「待验证」）
│   └── composite_findings.md         # 漏洞组合分析
├── phase4/
│   ├── validated_findings.md         # 已验证漏洞（与 phase3 结构对齐，别名）
│   ├── validation_results.json       # 验证结果（结构化）
│   └── rejected_findings.md          # 不成立候选
├── phase5/
│   ├── composite_findings.md         # 组合漏洞分析
│   └── primitive_chains.md           # 原语组合攻击链（audit-composer-agent 产出）
├── poc/
│   └── <finding-id>/                 # PoC 和验证证据
├── .archive/
│   └── <timestamp>/                  # 可选：过程文件归档副本（精简包时使用）
└── decompiled/                       # 可选：反编译输出（严禁清理）
```

## 最终报告规则

最终报告必须是 `audit/security_audit_report.md` 这一份文件。报告正文必须内联关键结论、复现细节、前置条件、调用链和修复建议，禁止用中间文件链接替代正文内容。

## 引用方式

报告中引用过程文件使用相对路径超链接：
- `[阶段2 批次1](phase2/findings_batch1.md)`
- `[vul-001 证据](poc/vul-001/result.md)`

## 过程文件保留策略

过程文件默认保留，用于证据追溯和复核。只有用户明确要求交付精简包时，才将过程文件归档到 `audit/.archive/<timestamp>/`；不得默认删除。`audit/decompiled` 目录严禁在任何清理操作中删除。
