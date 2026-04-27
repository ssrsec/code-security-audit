# 审计产出目录约定

## 目录结构

```text
audit/
├── security_audit_report.md
├── phase0/
│   ├── metrics.md
│   └── scope.md
├── phase1/
│   ├── project_inventory.json
│   ├── architecture_inventory.md
│   ├── auth_model.md
│   ├── in_scope_files.txt
│   ├── tier_list.json
│   ├── endpoint_list.md
│   ├── sink_list.md
│   ├── dependency_list.json
│   └── owasp_coverage_matrix.md
├── phase2/
│   ├── findings_batch{N}.md
│   ├── reviewed_paths_batch{N}.txt
│   ├── reviewed_paths_merged.txt
│   ├── candidate_findings.json
│   └── callchain_tracker.md
├── phase3/
│   ├── coverage_status.json
│   └── false_positive_notes.md
├── phase4/
│   ├── validated_findings.md
│   ├── validation_results.json
│   └── rejected_findings.md
├── phase5/
│   └── composite_findings.md
├── poc/
│   └── <finding-id>/
│       ├── README.md
│       ├── reproduce.http
│       ├── reproduce.py
│       ├── test_*.*
│       └── result.md
├── final/
│   ├── project_inventory.json
│   ├── owasp_coverage_matrix.md
│   ├── validation_results.json
│   ├── poc_index.md
│   └── residual_risk.md
└── decompiled/                       # 可选：反编译输出
```

## 保留策略

- 必须保留：`security_audit_report.md`、`audit/final/`、`audit/poc/`、`audit/decompiled/`。
- 应保留到交付完成：阶段 1 的项目画像、覆盖矩阵、阶段 4 的验证结果。
- 可清理：临时草稿、重复批次、失败的中间格式转换文件。

## 引用方式

最终报告应直接内联关键证据，不要求读者跳转中间文件才能理解漏洞。证据包可引用最终产物：

- `audit/final/project_inventory.json`
- `audit/final/owasp_coverage_matrix.md`
- `audit/final/validation_results.json`
- `audit/final/poc_index.md`

报告中的代码位置使用 `相对路径:行号`，例如 `src/main/java/app/UserController.java:45`。
