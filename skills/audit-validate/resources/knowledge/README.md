# 漏洞成立条件知识库索引

阶段 4 验证时，根据漏洞类型查阅对应文档，结合项目版本/配置判断 **已确认/待验证/不成立**，并映射到 V0-V4 验证等级（V1 = 待验证/HYPOTHESIS，V2/V3/V4 = 已确认/CONFIRMED）。**文档按漏洞类型与语言/框架扩展，不维护 SAST 规则库。**

---

## 与 OWASP Top 10 的对应关系

| OWASP Top 10 | 漏洞类型 | 文档 | 适用生态 |
|--------------|----------|------|----------|
| **A01** Broken Access Control | 授权/越权、URL 权限、权限表缺漏 | authorization_model.md | 通用 |
| **A02** Cryptographic Failures | 弱加密、密钥硬编码、敏感数据明文 | cryptographic_failures.md | 通用 |
| **A02/A05** Secrets / Hardcoded Credentials | 硬编码账号、密码、密钥、连接串 | `shared/secret_detection.md` | 通用 |
| **A03** Injection | SQL 注入 | sql_injection_conditions.md | 通用 |
| **A03** Injection | 命令/OS 注入 | command_os_injection_conditions.md | 通用 |
| **A03** Injection | SSTI（模板注入） | velocity_ssti_conditions.md 等 | Java/可扩展 |
| **A03** Injection | JNDI 注入 | jndi_conditions.md | Java |
| **A04** Insecure Design | 设计层面缺控（业务逻辑、缺授权设计） | 见 authorization_model + **parameter_and_business_logic.md** + audit-control 清单 | 通用 |
| **A05** Security Misconfiguration | 调试接口、默认凭据、CORS、错误泄露 | security_misconfiguration.md | 通用 |
| **A06** Vulnerable Components | 依赖版本、CVE | dependency_version_check.md + vuln-scanner | 通用 |
| **A07** Auth Failures | 认证/会话/密码策略/重置密码 | auth_failures.md | 通用 |
| **A08** Software/Data Integrity | 不安全反序列化 | insecure_deserialization.md、fastjson_conditions.md、xstream_conditions.md、jackson_conditions.md、shiro_deserialization_conditions.md、snakeyaml_conditions.md 等 | 通用 + 多生态 |
| **A09** Logging/Monitoring Failures | 日志不足、监控缺失 | 设计/运维向，可按需在 scope 中标 Low/Info | 通用 |
| **A10** SSRF | 服务端请求伪造 | ssrf_conditions.md | 通用 |
| （非 Top10） | 文件上传/路径穿越 | file_upload_conditions.md | 通用 |
| （通用） | 参数与业务逻辑（再下结论） | **parameter_and_business_logic.md** | 通用 |
| （非 Top10） | Fastjson 反序列化（Java） | fastjson_conditions.md | Java |

---

## 验证等级映射

| 等级 | 当前语义 |
|------|----------|
| V0 | 代码线索，只能留在候选或残余风险 |
| V1 / 待验证 / HYPOTHESIS | 静态可达，缺少运行时条件；必须进入报告，不得丢弃 |
| V2/V3/V4 / 已确认 / CONFIRMED | 通过单元/集成/端到端验证；最高可信已确认 |
| Info/建议项 | 不进入漏洞表，可进入覆盖矩阵、总体建议或残余风险 |

知识库文档中的历史标记 `HYPOTHESIS/CONFIRMED` 与 V1/V2-V4 等价。实际输出必须以 `shared/verification_principles.md` 的 V0-V4 为准。

---

## 默认不纳入"真实危害"的类型（见 audit_discipline）

- **强交互 CSRF**（用户必须点击/访问恶意页面才触发）→ 默认不进入最终漏洞表，除非用户要求或满足例外。
- **A09 日志/监控**：多为加固建议，可进入总体建议或残余风险，不默认作为漏洞。

---

## 按漏洞类型（简表）

| 漏洞类型 / 审计对象 | 文档 | 适用生态 |
|---------------------|------|----------|
| 授权/拦截层 | authorization_model.md | 通用 |
| 依赖版本获取 | dependency_version_check.md | 通用 |
| SQL 注入 | sql_injection_conditions.md | 通用 |
| 命令/OS 注入 | command_os_injection_conditions.md | 通用 |
| SSRF | ssrf_conditions.md | 通用 |
| 文件上传/存储 | file_upload_conditions.md | 通用 |
| **参数与业务逻辑** | **parameter_and_business_logic.md** | 通用 |
| 加密/敏感数据 | cryptographic_failures.md | 通用 |
| 安全配置错误 | security_misconfiguration.md | 通用 |
| 认证缺陷 | auth_failures.md | 通用 |
| 不安全反序列化（通用） | insecure_deserialization.md | 通用 |
| Fastjson（Java） | fastjson_conditions.md | Java |
| XStream（Java） | xstream_conditions.md | Java |
| Jackson 多态反序列化 | jackson_conditions.md | Java |
| Shiro RememberMe | shiro_deserialization_conditions.md | Java |
| SnakeYAML / YAML | snakeyaml_conditions.md | Java/Python |
| Java 原生反序列化 | java_native_deserialization_conditions.md | Java |
| Python pickle/PyYAML | python_pickle_conditions.md | Python |
| PHP unserialize | php_unserialize_conditions.md | PHP |
| .NET formatter/ViewState | dotnet_deserialization_conditions.md | .NET |
| JNDI（Java） | jndi_conditions.md | Java |
| Velocity SSTI（Java） | velocity_ssti_conditions.md | Java |
| Thymeleaf SSTI | （可添加 thymeleaf_conditions.md） | Java |

---

## 如何扩展（新漏洞 / 新语言）

1. **新漏洞类型**：在本目录新增 `xxx_conditions.md`，结构建议：**发现条件** + **成立条件**（按版本/配置/依赖）+ **如何获取版本/配置** + **报告约定**。
2. **新语言/框架**：可复制现有文档（如 Fastjson/Velocity），改为对应生态的库与路径，保持上述结构。
3. **通用类**：文档内用多语言/多框架示例（Java/Node/Python/PHP/Go/.NET），避免只写一种技术栈。

**不写**：正则规则库、引擎 if-else、针对某项目的定制路径。
