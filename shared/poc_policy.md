# PoC 安全与证据完整性策略

本文件合并了 PoC 安全边界和证据完整性要求，是阶段 4 和阶段 6 的 PoC 相关单一参考文档。

---

## 第一部分：PoC 安全边界

PoC 的目标是让研发团队复现、确认和修复漏洞，不是最大化攻击效果。默认采用最小、无害、可清理、可复算的证据。

### 1. 输出原则

必须提供：

- 可复现的请求、脚本、测试或断言。
- 前置条件、执行步骤、预期安全行为、实际结果、判定标准。
- 清理步骤或无需清理的理由。
- 脱敏后的证据和限制说明。

不得提供：

- 破坏性 payload，例如删除数据、写 crontab、反弹 shell、下载执行二进制、真实转账、批量发送垃圾请求。
- 真实凭据、完整私钥、可直接滥用的生产 token。
- 与授权范围无关的外带、持久化、横向移动或后门步骤。

### 2. 允许的运行时变量

反占位符规则仍然生效，但以下运行时变量允许使用：

| 变量 | 允许条件 |
|------|----------|
| `{{access-token}}` | 前置步骤必须给出获取 token 的具体请求或命令 |
| `{{csrf-token}}` | 前置步骤必须给出从页面或接口获取 token 的方式 |
| `{{resource-id}}` | 前置步骤必须给出枚举接口、样例格式和替换来源 |
| `127.0.0.1:<port>` | 端口必须来自项目配置、默认配置或测试环境说明 |

禁止 `REPLACE_XXX`、`YOUR_HOST`、`TODO`、`...`、`此处从略` 等空洞占位。

### 3. 漏洞类型安全要求

- RCE/命令执行：使用 `id`、`whoami`、`pwd`、`echo` 等无害命令。
- SQL 注入：优先使用时间延迟、错误回显、只读查询或事务回滚。
- 文件读：优先读取应用内测试文件或无敏感样本；真实敏感文件只在明确授权环境中验证并脱敏。
- 文件写：只写临时测试文件，必须清理。
- SSRF：优先使用本地 mock server、授权内网测试服务或用户提供的回连服务。
- 越权/未授权：使用测试账号、mock 权限或最小业务数据，不做真实敏感操作。
- Secret：验证可用性时优先使用只读、低权限、受控请求；报告展示必须脱敏。

### 4. 实战利用章节

最终报告应保留实战利用分析能力，但利用说明必须服务于授权防御验证和修复。

- 已确认高危/严重漏洞：至少给出 2 个具体场景，每个场景包含完整请求、payload、脚本、测试断言或安全等价证明。
- 待验证漏洞：至少给出 2 个假设验证通过后的场景，并明确条件假设和运行时待确认点。
- 中低危漏洞：至少给出一个具体影响场景；如能与其他漏洞组合，进入阶段 5 分析。
- 反序列化、注入、SSRF、文件、越权等漏洞的利用说明必须与阶段 4 证据一致，不得引入未经验证的新能力。

所有场景仍必须遵守无害、授权、可清理原则。需要展示危险能力时，优先使用 mock、测试断言、只读查询、无害命令或回滚事务作为安全等价证明。

---

## 第二部分：PoC 证据完整性要求

### 1. 每个 PoC 的证据包

目录：`audit/poc/<finding-id>/`

建议文件：

- `README.md`：漏洞编号、验证等级、环境、账号权限、执行步骤、安全限制、清理步骤。
- `reproduce.http` 或 `reproduce.py`：可执行请求或脚本。
- `test_*`：项目内最小单元/集成测试。
- `result.md`：实际执行结果摘要。
- `evidence.json`：结构化证据元数据。

### 2. `evidence.json` 最小字段

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

### 3. 证据质量要求

- 记录执行时间，不能只写"已验证"。
- 记录命令、请求、响应摘要、stdout/stderr/exit code 或测试断言。
- SQL 时间盲注记录 baseline 与 attack 多次采样。
- RCE/命令执行记录命令输出位置。
- 未授权/越权记录权限对照请求。
- Secret 验证记录脱敏后的服务响应或身份查询结果。
- 证据文件建议计算 SHA-256，报告中引用 hash。

### 4. 脱敏与安全

- Authorization、Cookie、Set-Cookie、API key、password、private key、JWT 等必须脱敏。
- 保留足够定位信息，例如 key 类型、前后 4 位、账号角色、目标服务名。
- 不在报告中输出真实生产 secret 全文。

### 5. 报告准入

漏洞进入最终报告前，至少满足：

- `validated_findings.md` 有结论。
- `validation_results.json` 有验证等级和结果。
- PoC/测试有执行方式和实际结果。
- 高危/严重漏洞必须有 `result.md` 或 `evidence.json`；无法运行时必须说明缺失条件并标待验证。
