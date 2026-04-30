# 动态扫描集成规范（DAST Integration）

定义 code-security-audit 如何通过 MCP 协议对接外部动态扫描工具，在静态审计基础上增加运行时验证能力。

---

## 1. 设计目标

将 DAST 能力作为 Phase 4 验证的**可选增强**，用于提升 V1（待验证）漏洞的验证等级：

```
Phase 2 候选漏洞 → Phase 4 静态验证（V1/V2）→ DAST 动态验证（V3/V4）
```

- DAST 不是必需组件：无 DAST 时，审计流程正常完成（静态验证即可）。
- DAST 是精度增强：有 DAST 时，V1 待验证漏洞可通过动态测试升级到 V3/V4。

---

## 2. MCP Server 接口规范

### 2.1 工具定义

DAST MCP Server 应提供以下工具：

#### `dast_scan`

对指定 URL/端点执行动态安全扫描。

```json
{
  "name": "dast_scan",
  "description": "对目标 URL 执行动态安全扫描",
  "parameters": {
    "target_url": { "type": "string", "description": "目标 URL" },
    "scan_type": {
      "type": "string",
      "enum": ["quick", "full", "targeted"],
      "description": "扫描类型：quick（5分钟内）、full（完整扫描）、targeted（针对特定漏洞类型）"
    },
    "vuln_types": {
      "type": "array",
      "items": { "type": "string" },
      "description": "针对性扫描的漏洞类型列表（targeted 模式必填）"
    },
    "auth_config": {
      "type": "object",
      "description": "认证配置（可选）",
      "properties": {
        "type": { "type": "string", "enum": ["bearer", "cookie", "basic", "custom"] },
        "token": { "type": "string" },
        "login_url": { "type": "string" },
        "credentials": { "type": "object" }
      }
    }
  }
}
```

#### `dast_verify`

对特定漏洞候选执行定向验证。

```json
{
  "name": "dast_verify",
  "description": "对特定漏洞候选执行动态验证",
  "parameters": {
    "finding_id": { "type": "string", "description": "候选漏洞 ID" },
    "endpoint": { "type": "string", "description": "目标端点" },
    "method": { "type": "string", "description": "HTTP 方法" },
    "vuln_type": { "type": "string", "description": "漏洞类型（sqli/xss/ssrf/rce/...）" },
    "payload_hints": {
      "type": "array",
      "items": { "type": "string" },
      "description": "从静态分析得到的 payload 提示（参数名、注入点等）"
    },
    "auth_config": { "type": "object", "description": "认证配置" }
  }
}
```

#### `dast_status`

查询扫描状态。

```json
{
  "name": "dast_status",
  "description": "查询正在进行的扫描状态",
  "parameters": {
    "scan_id": { "type": "string", "description": "扫描任务 ID" }
  }
}
```

#### `dast_results`

获取扫描结果。

```json
{
  "name": "dast_results",
  "description": "获取扫描结果",
  "parameters": {
    "scan_id": { "type": "string", "description": "扫描任务 ID" },
    "severity_filter": {
      "type": "string",
      "enum": ["all", "high", "critical"],
      "description": "按严重性过滤"
    }
  }
}
```

### 2.2 返回格式

所有 DAST 工具返回统一的 JSON 格式：

```json
{
  "scan_id": "dast-001",
  "status": "completed",
  "findings": [
    {
      "id": "dast-f-001",
      "type": "sql_injection",
      "severity": "high",
      "endpoint": "/api/users?id=1",
      "method": "GET",
      "parameter": "id",
      "evidence": {
        "request": "GET /api/users?id=1' OR '1'='1",
        "response_snippet": "error in SQL syntax...",
        "response_code": 500
      },
      "confidence": "confirmed",
      "static_finding_id": "SINK-003"
    }
  ],
  "scan_duration_ms": 15000,
  "urls_tested": 42
}
```

---

## 3. 集成架构

```
audit-validate-agent
    │
    ├── 静态验证（默认）
    │   └── 代码分析 → V1/V2
    │
    └── DAST 增强验证（可选）
        │
        ├── 检测 MCP Server 可用性
        │   └── 工具列表中包含 dast_verify → 启用
        │
        ├── 生成验证计划
        │   └── 从 V1 漏洞中筛选可动态验证的候选
        │
        ├── 执行动态验证
        │   └── dast_verify(finding_id, endpoint, ...)
        │
        └── 合并结果
            ├── DAST 确认 → 升级到 V3
            ├── DAST 未触发 → 保持 V1（不降级）
            └── DAST 发现新漏洞 → 追加到 findings
```

---

## 4. 安全约束

### 4.1 扫描安全

- DAST 扫描**仅在用户明确授权后执行**。
- 默认使用 `quick` 模式，避免破坏性测试。
- 所有 payload 使用无害检测方式（如时间盲注、布尔盲注），避免数据修改。
- 禁止对生产环境执行 DAST（需用户确认目标环境）。

### 4.2 作用域限制

- DAST 仅验证 Phase 2 已发现的候选漏洞。
- 不执行无目标的全面扫描（由用户主动触发除外）。
- 扫描范围限制在已枚举的端点列表内。

### 4.3 结果处理

- DAST 结果与静态分析结果关联（通过 `static_finding_id`）。
- DAST 确认 ≠ 自动升级严重性，最终评估仍由 validate-agent 判断。
- DAST 新发现的漏洞需回溯到代码，确认是否在静态分析中遗漏。

---

## 5. 兼容的 DAST 工具

本规范设计为工具无关，任何实现了上述 MCP 接口的 DAST 工具均可集成：

| 工具 | 适用场景 | 备注 |
|------|---------|------|
| OWASP ZAP | Web 应用全面扫描 | 开源，社区活跃 |
| Nuclei | 基于模板的漏洞检测 | 快速，模板丰富 |
| Burp Suite | 专业渗透测试 | 商业，功能全面 |
| sqlmap | SQL 注入验证 | 针对性强 |
| 自定义 MCP Server | 封装任意 DAST 工具 | 灵活 |

---

## 6. Phase 4 集成流程

audit-validate-agent 在验证漏洞时的增强流程：

1. **检测 DAST 可用性**：检查环境中是否有 DAST MCP Server。
2. **无 DAST**：按现有流程纯静态验证（V0-V2）。
3. **有 DAST**：
   a. 静态验证完成后，筛选 V1 漏洞中适合动态验证的候选。
   b. 询问用户是否授权执行 DAST。
   c. 授权后，对每个候选执行 `dast_verify`。
   d. 合并 DAST 结果，更新验证等级。
   e. DAST 新发现回溯到代码确认。

## 7. 当前状态

- **规范已定义**：MCP 接口规范完成。
- **实现待开发**：需要创建 DAST MCP Server 适配器。
- **集成待实现**：validate-agent 的 DAST 调用逻辑待添加。
