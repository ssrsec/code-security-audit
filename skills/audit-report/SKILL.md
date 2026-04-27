---
name: audit-report
description: 阶段 6 最终报告生成。整合项目画像、覆盖矩阵、验证结果、PoC、组合漏洞、修复建议和残余风险，输出可交付报告与最终证据包。
---

# 审计报告生成（阶段 6）

## 角色

负责阶段 6：生成最终报告 `audit/security_audit_report.md`，并整理 `audit/final/` 证据包。报告全文使用简体中文，代码、payload、标准名和命令保持原文。

## 输入

- `audit/phase1/project_inventory.json`
- `audit/phase1/architecture_inventory.md`
- `audit/phase1/auth_model.md`
- `audit/phase1/owasp_coverage_matrix.md`
- `audit/phase2/coverage_status.json`
- `audit/phase3/false_positive_notes.md`
- `audit/phase4/validated_findings.md`
- `audit/phase4/validation_results.json`
- `audit/phase4/rejected_findings.md`
- `audit/phase5/composite_findings.md`
- `audit/poc/`

## 报告结构

按 `shared/report_fields.md` 输出，至少包含：

1. 项目代码审计总结。
2. 项目基础架构画像。
3. 审计范围与覆盖矩阵。
4. 漏洞汇总表。
5. 漏洞详情。
6. 组合漏洞与攻击链。
7. PoC/测试验证结果。
8. 总体安全建议与残余风险。

## 必填内容

### 项目基础架构

必须从阶段 1 产物提炼：

- 目录结构、语言、框架、构建系统、运行方式。
- 认证逻辑、授权逻辑、租户隔离、拦截器。
- 入口清单摘要。
- 依赖和供应链风险。
- 信任边界和高价值资产。

### 覆盖与限制

必须说明：

- 文件覆盖率：`已审 X / 应审 Y = 100%`。
- OWASP/ASVS/WSTG/CWE 覆盖摘要。
- 不适用项、未覆盖项和无法验证项。
- 不得声称“发现所有漏洞”。

### 漏洞详情

每条漏洞必须包含：

- 编号、名称、严重性、验证状态、验证等级。
- CWE、OWASP、ASVS/WSTG、CVSS 向量和理由。
- 前置条件、访问权限、影响资产。
- 调用链和代码证据。
- PoC/测试步骤、命令、预期结果、实际结果。
- 修复建议和回归测试建议。
- 待验证条件或残余风险。

V0 不进入漏洞详情。V1 只能作为待验证。触发条件不成立的 finding 只在误报/排除摘要或残余风险中说明，不进入漏洞汇总表。

## 证据包整理

生成或复制：

- `audit/final/project_inventory.json`
- `audit/final/owasp_coverage_matrix.md`
- `audit/final/validation_results.json`
- `audit/final/poc_index.md`
- `audit/final/residual_risk.md`

`poc_index.md` 必须列出每个 PoC/测试的路径、验证等级、执行命令、安全限制和清理步骤。

## 完成度校验

报告生成前必须确认：

- 覆盖率已达到 100% 或报告明确说明因平台/授权边界无法继续，并列入残余风险。
- 阶段 4 已完成验证分级。
- 阶段 5 已完成组合漏洞分析。
- 每条漏洞字段完整。
- 报告没有编造文件、行号、调用链、依赖版本、执行结果。

## 清理策略

- 保留 `audit/security_audit_report.md`、`audit/final/`、`audit/poc/`、`audit/decompiled/`。
- 不强制删除阶段 1/4 关键证据；如需要清理，只清理临时草稿、重复批次和失败转换文件。
- 不得执行会删除最终证据包的命令。

## 输出

- `audit/security_audit_report.md`
- `audit/final/`
