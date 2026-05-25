# 原语组合规则表（Primitive Chain Catalog）

本规则表供 `audit-primchain-agent` 的 Step 2（规则表快速命中）使用。
每条规则定义一个已知的安全原语组合模式，包含所需原语、约束传播逻辑和组合结果。

**规则扩展约定：**
- 新增规则追加 JSON 块，`rule_id` 按 `CHAIN-RULE-NNN` 递增
- `resulting_severity` 只允许 `严重 / 高危 / 中危`（原语组合不产出低危）
- `required_primitives` 含三项时为三跳链，引擎逻辑不变

---

## CHAIN-RULE-001

```json
{
  "rule_id": "CHAIN-RULE-001",
  "name": "受限写 + 定时任务 → 定时代码执行",
  "required_primitives": [
    { "capability": "constrained_write", "constraint_unlock_key": "cron_hijack" },
    { "capability": "scheduled_exec" }
  ],
  "constraint_propagation": "constrained_write 的路径约束须包含 cron 执行目录或通配符路径",
  "resulting_capability": "arbitrary_code_execution",
  "resulting_severity": "高危",
  "attack_narrative": "写入恶意脚本至 cron 可执行路径 → 等待定时触发 → RCE"
}
```

## CHAIN-RULE-002

```json
{
  "rule_id": "CHAIN-RULE-002",
  "name": "受限写 + 路径遍历解锁 → 任意写 Webshell",
  "required_primitives": [
    { "capability": "constrained_write", "constraint_unlock_key": "path_traversal_to_arbitrary_write" },
    { "capability": "constrained_write", "constraint_unlock_key": "path_traversal_to_arbitrary_write" }
  ],
  "constraint_propagation": "constrained_write 的路径前缀约束被路径遍历（../）序列突破",
  "resulting_capability": "arbitrary_write",
  "resulting_severity": "严重",
  "attack_narrative": "通过路径遍历绕过路径约束 → 向 Web 根目录写入 shell 文件 → RCE"
}
```

## CHAIN-RULE-003

```json
{
  "rule_id": "CHAIN-RULE-003",
  "name": "受限读 + 路径泄露解锁 → 任意文件读",
  "required_primitives": [
    { "capability": "constrained_read", "constraint_unlock_key": "path_traversal_to_arbitrary_write" },
    { "capability": "path_disclosure" }
  ],
  "constraint_propagation": "path_disclosure 提供真实路径，constrained_read 的路径约束被遍历序列突破",
  "resulting_capability": "arbitrary_file_read",
  "resulting_severity": "高危",
  "attack_narrative": "通过路径泄露获取真实路径 → 路径遍历绕过约束 → 读取任意文件"
}
```

## CHAIN-RULE-004

```json
{
  "rule_id": "CHAIN-RULE-004",
  "name": "SSRF + 内网反序列化 → 内网 RCE",
  "required_primitives": [
    { "capability": "ssrf" },
    { "capability": "deserialization_exec" }
  ],
  "constraint_propagation": "ssrf 突破网络隔离，使内网只监听 deserialization_exec 端点可达",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "通过 SSRF 访问内网反序列化端点 → 发送 gadget 链 payload → RCE"
}
```

## CHAIN-RULE-005

```json
{
  "rule_id": "CHAIN-RULE-005",
  "name": "SSRF + 云元数据端点 → 凭证窃取",
  "required_primitives": [
    { "capability": "ssrf" },
    { "capability": "credential_leak" }
  ],
  "constraint_propagation": "ssrf 访问 169.254.169.254 或类似元数据端点，获取 IAM 临时凭证",
  "resulting_capability": "credential_theft",
  "resulting_severity": "高危",
  "attack_narrative": "SSRF 请求云元数据地址 → 返回 IAM 密钥 → 横向移动"
}
```

## CHAIN-RULE-006

```json
{
  "rule_id": "CHAIN-RULE-006",
  "name": "SQL 注入 + 文件写权限 → INTO OUTFILE Webshell",
  "required_primitives": [
    { "capability": "sql_injection" },
    { "capability": "arbitrary_write" }
  ],
  "constraint_propagation": "sql_injection 具备 FILE 权限（MySQL），arbitrary_write 指向 Web 可执行目录",
  "resulting_capability": "web_shell",
  "resulting_severity": "严重",
  "attack_narrative": "SQL 注入写入 INTO OUTFILE → Web 根目录生成 shell 文件 → RCE"
}
```

## CHAIN-RULE-007

```json
{
  "rule_id": "CHAIN-RULE-007",
  "name": "Token 伪造 + 授权绕过 → 完全权限提升",
  "required_primitives": [
    { "capability": "token_forgery" },
    { "capability": "authz_bypass" }
  ],
  "constraint_propagation": "token_forgery 提供合法格式的高权限 token，authz_bypass 使该 token 被接受",
  "resulting_capability": "full_privilege_escalation",
  "resulting_severity": "严重",
  "attack_narrative": "伪造管理员 JWT → 绕过授权检查 → 全系统管理权限"
}
```

## CHAIN-RULE-008

```json
{
  "rule_id": "CHAIN-RULE-008",
  "name": "凭证泄露 + 认证绕过 → 账户接管",
  "required_primitives": [
    { "capability": "credential_leak" },
    { "capability": "authn_bypass" }
  ],
  "constraint_propagation": "credential_leak 提供账号密码或 token，authn_bypass 使攻击者以该身份登录",
  "resulting_capability": "account_takeover",
  "resulting_severity": "高危",
  "attack_narrative": "泄露的凭证重放登录接口 → 绕过认证 → 账户接管"
}
```

## CHAIN-RULE-009

```json
{
  "rule_id": "CHAIN-RULE-009",
  "name": "受限写 + 源码泄露 → 配置覆盖行为劫持",
  "required_primitives": [
    { "capability": "constrained_write", "constraint_unlock_key": "config_overwrite" },
    { "capability": "source_disclosure" }
  ],
  "constraint_propagation": "source_disclosure 暴露配置文件路径，constrained_write 覆盖配置影响业务行为",
  "resulting_capability": "behavior_hijack",
  "resulting_severity": "高危",
  "attack_narrative": "源码泄露获取配置路径 → 写入恶意配置 → 劫持应用逻辑"
}
```

## CHAIN-RULE-010

```json
{
  "rule_id": "CHAIN-RULE-010",
  "name": "模板注入 + 沙箱逃逸 → RCE",
  "required_primitives": [
    { "capability": "template_injection" },
    { "capability": "logic_bypass" }
  ],
  "constraint_propagation": "template_injection 在沙箱中执行，logic_bypass 提供逃逸路径（如 class 链、反射）",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "模板注入进入受限沙箱 → 利用逻辑绕过逃逸沙箱 → RCE"
}
```

## CHAIN-RULE-011

```json
{
  "rule_id": "CHAIN-RULE-011",
  "name": "竞态条件 + 授权绕过 → TOCTOU 权限提升",
  "required_primitives": [
    { "capability": "race_condition" },
    { "capability": "authz_bypass" }
  ],
  "constraint_propagation": "race_condition 在权限检查与操作执行之间创造窗口，authz_bypass 利用该窗口绕过检查",
  "resulting_capability": "privilege_escalation",
  "resulting_severity": "高危",
  "attack_narrative": "并发请求在权限检查后、操作执行前修改状态 → 绕过授权检查 → 提权"
}
```

## CHAIN-RULE-012

```json
{
  "rule_id": "CHAIN-RULE-012",
  "name": "原型链污染 + 表达式注入 → RCE",
  "required_primitives": [
    { "capability": "prototype_pollution" },
    { "capability": "expression_injection" }
  ],
  "constraint_propagation": "prototype_pollution 注入恶意属性到 Object 原型，expression_injection 在表达式求值时触发",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "污染 __proto__ 注入 gadget 属性 → 表达式引擎求值时触发代码执行"
}
```

## CHAIN-RULE-013

```json
{
  "rule_id": "CHAIN-RULE-013",
  "name": "开放重定向 + Token 伪造 → OAuth 回调劫持",
  "required_primitives": [
    { "capability": "open_redirect" },
    { "capability": "token_forgery" }
  ],
  "constraint_propagation": "open_redirect 劫持 OAuth 回调 URL，token_forgery 利用截获的授权码伪造 token",
  "resulting_capability": "account_takeover",
  "resulting_severity": "高危",
  "attack_narrative": "构造恶意 redirect_uri → 用户授权后 code 发至攻击者 → 用 code 换取 token → 账户接管"
}
```

## CHAIN-RULE-014

```json
{
  "rule_id": "CHAIN-RULE-014",
  "name": "受限读 + 凭证泄露 → 配置文件读取密钥",
  "required_primitives": [
    { "capability": "constrained_read", "constraint_unlock_key": "path_traversal_to_arbitrary_write" },
    { "capability": "credential_leak" }
  ],
  "constraint_propagation": "constrained_read 通过路径遍历读取配置文件，credential_leak 确认文件中存储明文凭证",
  "resulting_capability": "credential_theft",
  "resulting_severity": "高危",
  "attack_narrative": "路径遍历读取 application.yml/database.conf → 提取数据库/API 密钥"
}
```

## CHAIN-RULE-015

```json
{
  "rule_id": "CHAIN-RULE-015",
  "name": "SSRF + SQL 注入 + 文件写 → 三跳内网写 Shell",
  "required_primitives": [
    { "capability": "ssrf" },
    { "capability": "sql_injection" },
    { "capability": "arbitrary_write" }
  ],
  "constraint_propagation": "ssrf 到达内网 DB 服务，sql_injection 执行 INTO OUTFILE，arbitrary_write 写入 Web 目录",
  "resulting_capability": "remote_code_execution",
  "resulting_severity": "严重",
  "attack_narrative": "SSRF 访问内网 MySQL → SQL 注入执行 INTO OUTFILE → 写入 Webshell → RCE"
}
```
