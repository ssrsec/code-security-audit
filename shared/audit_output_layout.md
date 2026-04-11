# 审计产出目录约定

## 目录结构

```
audit/
├── security_audit_report.md          # 唯一交付报告
├── phase0/
│   └── metrics.md                    # 代码库度量
├── phase1/
│   ├── phase1_recon.md               # 技术栈、审计形态
│   ├── in_scope_files.txt            # 应审文件列表（覆盖率分母）
│   ├── tier_list.json                # Tier 分类
│   ├── coverage_matrix.md            # 覆盖矩阵
│   ├── endpoint_list.md              # 端点清单
│   ├── sink_list.md                  # 危险 API 清单
│   └── dependency_list.json          # 依赖清单
├── phase2/
│   ├── findings_batch{N}.md          # 各批次候选漏洞
│   ├── reviewed_paths_batch{N}.txt   # 各批次审阅文件
│   ├── reviewed_paths_merged.txt     # 合并审阅清单
│   ├── coverage_status.json          # 覆盖率状态
│   └── callchain_tracker.md          # 调用链追踪（可选）
├── phase3/
│   ├── findings_verified.md          # 已验证漏洞
│   └── composite_findings.md         # 组合漏洞分析
└── evidence/                         # 可选：代码片段/PoC 附件
```

## 引用方式

报告中引用过程文件使用相对路径超链接：
- `[阶段2 批次1](phase2/findings_batch1.md)`
- `[vul-001 证据](evidence/vuln-001-snippet.md)`
