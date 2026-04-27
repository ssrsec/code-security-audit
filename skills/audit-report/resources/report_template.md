# 安全审计报告

## 一、项目代码审计总结

| 字段 | 内容 |
|------|------|
| 审计目标 | {{ project_name }}（{{ project_path }}） |
| 审计模式 | {{ audit_mode }} |
| 版本/Commit | {{ commit_or_version }} |
| 开始时间 | {{ start_time_from_phase0 }} |
| 结束时间 | {{ generated_at_by_date_command }} |
| 文件覆盖率 | 已审 {{ reviewed_count }} / 应审 {{ in_scope_count }} = {{ completion_pct }}% |
| 标准覆盖 | {{ owasp_coverage_summary }} |
| 验证统计 | V1 {{ v1_count }} / V2 {{ v2_count }} / V3 {{ v3_count }} / V4 {{ v4_count }} |

### 发现统计

- 严重：{{ critical }} 个
- 高危：{{ high }} 个
- 中危：{{ medium }} 个
- 低危：{{ low }} 个
- 已确认：{{ confirmed_count }} 个
- 待验证：{{ pending_count }} 个
- 组合漏洞：{{ chain_count }} 个

## 二、项目基础架构画像

### 2.1 项目结构与技术栈

{{ architecture_summary }}

### 2.2 认证与授权逻辑

{{ auth_model_summary }}

### 2.3 依赖与供应链

{{ dependency_summary }}

### 2.4 信任边界与高价值资产

{{ trust_boundary_summary }}

## 三、审计范围与覆盖矩阵

### 3.1 文件和模块覆盖

{{ file_and_module_coverage }}

### 3.2 OWASP/ASVS/WSTG/CWE 覆盖

{{ standards_coverage }}

### 3.3 不适用项、未覆盖项和限制

{{ limitations }}

## 四、漏洞汇总表

| 漏洞编号 | 漏洞名称 | 严重性 | 验证状态 | 验证等级 | CWE | OWASP/ASVS/WSTG | 访问权限 | 影响资产 |
|---------|---------|--------|----------|----------|-----|-----------------|----------|----------|
| WB-001 | {{ title }} | {{ severity }} | {{ status }} | {{ validation_level }} | {{ cwe }} | {{ owasp_mapping }} | {{ privilege }} | {{ asset }} |

## 五、漏洞详情

### WB-001：{{ title }}

| 字段 | 内容 |
|------|------|
| 漏洞编号 | WB-001 |
| 漏洞名称 | {{ title }} |
| 漏洞描述 | {{ description }} |
| 严重性 | {{ severity }} |
| 验证状态 | {{ status }} |
| 验证等级 | {{ validation_level }} |
| CWE / OWASP | {{ cwe_owasp }} |
| CVSS | {{ cvss_vector_score_and_rationale }} |
| 前置条件 | {{ preconditions }} |
| 访问权限 | {{ privilege_required }} |
| 影响资产 | {{ impacted_assets }} |
| 调用链 | {{ call_chain_with_file_lines }} |
| 代码证据 | {{ code_evidence_summary }} |
| 待验证内容 | {{ pending_validation_items_if_any }} |

#### PoC/测试

{{ poc_or_test_steps_expected_actual_cleanup }}

#### 修复建议

{{ remediation_with_files_code_and_regression_tests }}

#### 残余风险

{{ residual_risk }}

## 六、组合漏洞与攻击链

{{ composite_findings }}

## 七、PoC/测试验证结果

{{ validation_results_summary }}

## 八、总体安全建议与残余风险

### 8.1 架构层面

{{ architecture_recommendations }}

### 8.2 开发流程

{{ sdlc_recommendations }}

### 8.3 高频漏洞统一修复

{{ common_fix_recommendations }}

### 8.4 依赖与安全运维

{{ operations_recommendations }}

### 8.5 残余风险

{{ residual_risk_summary }}
