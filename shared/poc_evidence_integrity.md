# PoC 证据完整性要求

本文件定义阶段 4 和阶段 6 对 PoC/测试证据的最小完整性要求，确保最终报告中的验证结果真实、可复核、可复现。

## 1. 每个 PoC 的证据包

目录：`audit/poc/<finding-id>/`

建议文件：

- `README.md`：漏洞编号、验证等级、环境、账号权限、执行步骤、安全限制、清理步骤。
- `reproduce.http` 或 `reproduce.py`：可执行请求或脚本。
- `test_*`：项目内最小单元/集成测试。
- `result.md`：实际执行结果摘要。
- `evidence.json`：结构化证据元数据。

## 2. `evidence.json` 最小字段

```json
{
  "findingId": "vul-001",
  "validationLevel": "V4",
  "generatedAt": "YYYY-MM-DDTHH:mm:ssZ",
  "environment": "user-test-env | local | unit | integration | mock",
  "target": "",
  "operator": "codex",
  "commands": [],
  "http": {
    "method": "",
    "url": "",
    "status": 0,
    "requestHeadersRedacted": {},
    "responseEvidence": ""
  },
  "process": {
    "stdout": "",
    "stderr": "",
    "exitCode": 0
  },
  "timing": {
    "baselineMs": null,
    "attackMs": null,
    "samples": []
  },
  "assertions": [],
  "artifacts": [
    {
      "path": "reproduce.py",
      "sha256": ""
    }
  ],
  "cleanup": "",
  "limitations": []
}
```

## 3. 证据质量要求

- 记录执行时间，不能只写“已验证”。
- 记录命令、请求、响应摘要、stdout/stderr/exit code 或测试断言。
- SQL 时间盲注记录 baseline 与 attack 多次采样。
- RCE/命令执行记录命令输出位置。
- 未授权/越权记录权限对照请求。
- Secret 验证记录脱敏后的服务响应或身份查询结果。
- 证据文件建议计算 SHA-256，报告中引用 hash。

## 4. 脱敏与安全

- Authorization、Cookie、Set-Cookie、API key、password、private key、JWT 等必须脱敏。
- 保留足够定位信息，例如 key 类型、前后 4 位、账号角色、目标服务名。
- 不在报告中输出真实生产 secret 全文。

## 5. 报告准入

漏洞进入最终报告前，至少满足：

- `validated_findings.md` 有结论。
- `validation_results.json` 有验证等级和结果。
- PoC/测试有执行方式和实际结果。
- 高危/严重漏洞必须有 `result.md` 或 `evidence.json`；无法运行时必须说明缺失条件并标待验证。
