# 白盒审计 Schema 与证据约定

本文定义项目画像、覆盖矩阵、finding 和验证结果的最小字段。阶段产物可以扩展字段，但不得缺少这里列出的核心信息。

## 1. 项目画像 `project_inventory.json`

```json
{
  "meta": {
    "projectName": "",
    "projectRoot": "",
    "commit": "",
    "generatedAt": "",
    "auditMode": "source_only | compiled_only | both"
  },
  "languages": [
    {
      "name": "Java",
      "version": "",
      "loc": 0,
      "mainPaths": []
    }
  ],
  "frameworks": [],
  "buildSystems": [],
  "runtimeServices": [],
  "dataStores": [],
  "externalServices": [],
  "entryPoints": [],
  "authn": {
    "type": "",
    "sessionMechanism": "",
    "tokenLocation": "",
    "loginEndpoints": []
  },
  "authz": {
    "model": "RBAC | ABAC | ACL | custom | unknown",
    "globalInterceptors": [],
    "resourceOwnershipChecks": [],
    "tenantIsolation": ""
  },
  "dependencies": [],
  "sensitiveSinks": [],
  "securityControls": [],
  "unknowns": []
}
```

## 2. 架构画像 `architecture_inventory.md`

必须包含：

- 目录结构和模块职责。
- 开发语言、框架、构建系统、运行方式。
- HTTP/RPC/消息队列/任务调度入口。
- 数据库、缓存、对象存储、搜索引擎、第三方 API。
- 认证流程、会话或 token 生命周期。
- 授权模型、租户隔离、资源归属校验位置。
- 信任边界：用户、前端、后端、内部服务、数据库、文件系统、外部服务。
- 高价值资产：用户数据、订单/支付、凭据、后台管理、文件、配置、密钥。
- 依赖风险：已知高危组件、反序列化 gadget、动态执行库、模板引擎。

## 3. OWASP 覆盖矩阵

```json
{
  "standard": "OWASP ASVS/WSTG/Top10 + CWE",
  "items": [
    {
      "domain": "Access Control",
      "asvs": ["V4"],
      "wstg": ["WSTG-ATHZ"],
      "owaspTop10": ["A01:2021-Broken Access Control"],
      "cwe": ["CWE-862", "CWE-863", "CWE-639"],
      "applicable": true,
      "targets": ["controllers/*", "security config", "tenant filters"],
      "status": "not-started | in-progress | covered | not-applicable",
      "evidence": [],
      "findings": [],
      "limitations": []
    }
  ]
}
```

状态要求：

- `not-started`：尚未审。
- `in-progress`：已覆盖部分文件或部分入口。
- `covered`：适用范围内已审完，并有证据或排除理由。
- `not-applicable`：不适用，必须写原因。

## 4. 候选 finding `candidate_findings.json`

```json
{
  "id": "WB-AUTHZ-001",
  "title": "",
  "category": "authz | authn | injection | deserialization | ssrf | file | crypto | secret | business-logic | supply-chain",
  "owasp": [],
  "asvs": [],
  "wstg": [],
  "cwe": [],
  "severityHypothesis": "critical | high | medium | low",
  "validationLevel": "V0 | V1",
  "entryPoint": {
    "type": "HTTP | RPC | MQ | CLI | Scheduler | File",
    "location": "",
    "authRequired": "none | low-privileged | admin | unknown"
  },
  "sourceToSink": [
    {
      "file": "",
      "line": 0,
      "symbol": "",
      "evidence": ""
    }
  ],
  "controlsObserved": [],
  "controlsMissing": [],
  "attackPreconditions": [],
  "impact": "",
  "skepticChecksNeeded": [],
  "notes": ""
}
```

## 5. 验证等级

| 等级 | 名称 | 含义 | 是否可作为已确认漏洞 |
|------|------|------|----------------------|
| V0 | 代码线索 | 存在危险 API、可疑版本或可疑端点，但未闭环 | 否 |
| V1 | 静态可达 | 外部输入到危险点或控制缺失的调用链可静态证明 | 可作为“待验证”，不宜标“已确认” |
| V2 | 单元验证 | 用最小单元测试、函数级 PoC 或 mock 证明关键条件 | 可作为已确认或待验证，视运行时依赖 |
| V3 | 集成验证 | 在本地项目运行、集成测试或容器环境验证 | 可作为已确认 |
| V4 | 授权环境 E2E | 在用户提供测试环境端到端验证 | 可作为最高可信已确认 |

## 6. 验证结果 `validation_results.json`

```json
{
  "findingId": "WB-AUTHZ-001",
  "validationLevel": "V4",
  "environment": "user-provided-test-env | local-integration | unit-test | static-only",
  "pocPath": "audit/poc/WB-AUTHZ-001/",
  "commands": [],
  "expected": "",
  "actual": "",
  "verified": true,
  "cvss": {
    "version": "3.1",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "score": 8.1,
    "rationale": ""
  },
  "safeExecution": {
    "destructive": false,
    "cleanup": "",
    "limitations": []
  }
}
```

## 7. 最终报告中的 finding 字段

每条漏洞至少包含：

- 漏洞编号、名称、等级、验证状态、验证等级。
- OWASP Top 10、ASVS/WSTG、CWE、CVSS 向量和理由。
- 影响资产、触发入口、访问权限、前置条件。
- 完整调用链，每一跳为 `文件:行号`。
- 代码证据摘要。
- PoC 或测试步骤、执行结果、预期结果、清理步骤。
- 修复建议：具体文件、修改点、修复原理、回归测试建议。
- 残余风险或未验证条件。

## 8. PoC 文件约定

每个 finding 可在 `audit/poc/<finding-id>/` 下保存：

- `README.md`：目的、前置条件、执行方式、预期结果、清理步骤。
- `reproduce.http`：HTTP/Burp 可复现请求。
- `reproduce.py`：非 HTTP 或多步骤验证脚本。
- `test_*.py`、`*.spec.ts`、`*.test.ts`、`*Test.java`：最小化测试。
- `result.md`：实际执行结果、截图或日志摘要。

PoC 必须避免破坏性操作。确需证明高危影响时，用无害命令、只读接口、mock 资源或回滚事务。
