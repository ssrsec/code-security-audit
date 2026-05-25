---
name: audit-recon
description: 阶段 1 项目侦察。识别技术栈、枚举端点、Tier 分类、生成应审文件列表与覆盖矩阵。不做漏洞定性（→ audit-sink / audit-control）、不做单漏洞验证（→ audit-validate）。当 audit-orchestrator 进入 Phase 1，或用户说「开始侦察 / 识别技术栈 / 枚举端点」时触发。
---

# 阶段 1 项目侦察

## Banned Patterns（零容忍）

- 禁止：编造文件路径或代码片段；所有 `file:line` 必须来自实际 Read/Glob 输出。
- 禁止：无法判断审计形态（source_only / compiled_only / both）时擅自假设；必须**询问用户**。
- 禁止：识别框架/技术栈时凭直觉填写；必须从 `pom.xml / build.gradle / package.json / requirements.txt / *.csproj` 等构建文件取证。
- 禁止：跳过 `unknowns` 记录；本阶段未确认的事实必须显式列入 `unknowns` 字段。
- 禁止：在 `in_scope_files.txt` 中遗漏覆盖率分母（任何"略过的文件"必须写排除原因）。

## 角色

阶段 1：建立项目基础架构画像和攻击面地图。**不做漏洞定性**，只收集可验证事实，为阶段 2-4 提供覆盖分母、入口、sink、鉴权模型、依赖版本、标准覆盖矩阵。

## 输入

- 阶段 0 的 `metrics.md`、`scope.md`
- 项目根路径
- 反编译输出路径（如存在）

## 执行步骤

### 1. 项目结构与技术栈识别

用 `rg --files`、`find`、构建文件和配置文件识别：

- 开发语言、版本、主要目录
- 框架与中间件
- 构建系统
- 运行方式：单体、前后端分离、微服务、Serverless、CLI、定时任务

> 主流框架对照表见 `shared/framework_catalog.md`（按需读取，遇到陌生框架时查）。

输出到 `audit/phase1/project_inventory.json` 和 `audit/phase1/architecture_inventory.md`。

### 2. 认证与授权模型

按 `shared/framework_authz_checklist.md` 单独分析，输出 `audit/phase1/auth_model.md` 与 `audit/phase1/framework_authz_map.md`：

- 登录、注册、找回密码、SSO/OAuth/OIDC、回调入口
- session/JWT/API key/cookie/header 的存储、生命周期、刷新逻辑
- 全局 Filter/Interceptor/Middleware/Gateway/SecurityConfig
- RBAC/ABAC/ACL/自定义权限模型
- 资源归属校验、租户隔离、管理员权限边界
- 白名单、匿名接口、内部接口、调试接口
- 框架专项（Spring Security/Shiro/Sa-Token/RuoYi/DRF/NestJS Guard/Laravel Middleware/ASP.NET Authorization）

无法确认时写入 `unknowns`，不得猜测。

### 3. 通用系统/产品识别与历史漏洞情报

许多审计目标是知名开源项目或通用系统的部署实例（或基于它们的二次开发）。识别目标身份后，可利用公开的历史漏洞、安全分析文章大幅提升审计效率和覆盖率。

**3.1 识别目标系统身份**

通过以下线索判断审计目标是否为已知系统：

| 线索类型 | 检测方式 |
|---------|---------|
| 项目名称 | README、`pom.xml` 的 `<name>`/`<artifactId>`、`package.json` 的 `name`、登录页标题 |
| 框架指纹 | RuoYi（`com.ruoyi`）、Jeecg（`org.jeecg`）、若依（`ry-`前缀）、SpringBlade（`org.springblade`）、pigx、guns、jeesite |
| CMS/平台 | WordPress（`wp-content/`）、Drupal（`sites/default/`）、Django Admin（`/admin/`特征）、Strapi、Keycloak |
| 中间件/工具 | Jenkins（`JENKINS_HOME`）、GitLab、Nexus、SonarQube、Grafana、Nacos、Apollo、XXL-Job、MinIO |
| 版本标记 | 版本号在配置文件、启动日志、关于页面中 |

**3.2 历史漏洞情报收集（识别到已知系统时必须执行）**

确认目标是已知系统后，按 `shared/external_knowledge_protocol.md` 联网搜索：

| 搜索内容 | 查询模板 | 输出 |
|---------|---------|------|
| 已知 CVE | `<系统名> <版本> CVE site:nvd.nist.gov` | CVE 编号、影响版本、漏洞类型 |
| 安全分析文章 | `<系统名> 漏洞分析 / security vulnerability analysis` | 漏洞原理、利用路径、受影响端点 |
| 历史安全公告 | `<系统名> security advisory / 安全更新` | 官方修复的漏洞列表 |
| 公开 PoC/Exploit | `<系统名> <版本> exploit / PoC` | 利用方式、工具、payload |
| 默认凭证 | `<系统名> default credentials / 默认密码` | 默认账号密码列表 |

**3.3 情报输出**

将收集到的情报写入 `audit/phase1/known_system_intel.md`：

```markdown
## 目标系统识别

- 系统名称：RuoYi v4.7.6
- 识别依据：pom.xml artifactId=ruoyi-admin, com.ruoyi 包名
- 官方仓库：https://github.com/yangzongzhuan/RuoYi

## 已知历史漏洞（与当前版本相关）

| CVE/编号 | 漏洞类型 | 影响版本 | 与当前版本关系 | 来源 URL | Phase 2 优先检查 |
|---------|---------|---------|-------------|---------|---------------|
| CVE-2024-XXXXX | SQL 注入 | ≤4.7.5 | 当前版本可能已修复 | [NVD](url) | 验证修复是否完整 |
| 历史漏洞-001 | 任意文件读取 | 全版本 | 需验证 | [分析文章](url) | 检查 /common/download 接口 |

## 高价值审计线索（基于历史漏洞总结）

- 重点检查端点：/system/user/export, /common/download, /monitor/...
- 已知攻击面：定时任务 RCE、SQL 注入（数据导出接口）、Shiro 反序列化
- 默认凭证：admin/admin123
- 已知绕过手法：Shiro 路径规范化绕过、SQL 注入在 MyBatis ${}
```

**3.4 情报驱动审计**

Phase 2 审计时，sink-agent 和 control-agent 的 prompt 中注入 `known_system_intel.md` 的关键信息，让它们优先检查已知高风险区域，同时不遗漏全量覆盖。

**3.5 非已知系统**

未识别到已知系统时，跳过本步骤，仅在 `audit/phase1/known_system_intel.md` 写入：`> 未识别到已知通用系统，跳过历史漏洞情报收集。`

### 4. 依赖、Secret 与供应链画像

输出 `audit/phase1/dependency_list.json`：

- 直接依赖和锁定版本
- 已知高危组件线索（参照 `shared/sink_catalog_by_lang.md` "A06 高危组件"表）
- Java classpath / `WEB-INF/lib` / `lib` / `node_modules` / `vendor` 中可作 gadget 的依赖
- Secret、私有 registry、脚本安装钩子、postinstall 等供应链线索

**遇到陌生依赖或不确定是否在 CVE 影响范围内 → 按 `shared/external_knowledge_protocol.md` §2 表 #3 联网查 NVD**；查询结果必须留 URL 写入 `dependency_list.json` 的 `cve_evidence` 字段。**禁止编造 CVE 编号或编造"未受影响"结论。** 无搜索结果时记入 `unknowns`，让 phase4 验证。

按 `shared/secret_detection.md` 输出 `audit/phase1/secret_inventory.md`：

- 硬编码账号、密码、API key、JWT secret、数据库/Redis/MQ 连接串、私钥、证书、云厂商 AK/SK
- 标记来源 `file:line`、加载 profile、是否生产可达、是否已脱敏、验证等级
- 示例值或不可达测试值必须记录排除理由

### 5. 入口枚举

输出 `audit/phase1/endpoint_list.md`，覆盖：

- HTTP API、页面路由、WebSocket、GraphQL、gRPC、RPC、MQ consumer、CLI、定时任务、文件导入
- 必审入口关键词：`login / register / oauth / sso / callback / admin / role / permission / tenant / export / download / upload / payment / delete / reset / debug / internal / actuator`
- 格式：`HTTP方法 | 路径 | Handler文件:行号 | 是否需认证 | 权限要求 | 资产/风险`

### 6. Sink 与危险能力枚举

输出 `audit/phase1/sink_list.md`，按以下安全域覆盖：

- 命令执行 / 动态代码 / 反序列化
- SQL/NoSQL/LDAP/XPath/ORM raw query
- SSRF / URL fetch / 代理 / 回调
- 文件上传/下载/读取/写入/解压
- 加解密 / 签名 / JWT / 随机数 / 密码哈希
- 权限变更 / 角色分配 / 租户切换 / 高价值数据导出
- 模板 / 表达式（SSTI、SpEL、OGNL、Velocity、FreeMarker、Handlebars、公式）

> 各语言典型 Sink API 与高危组件清单见 `shared/sink_catalog_by_lang.md`（按需读取）。本步骤主体写"按域汇总"，不在 sink_list.md 重复罗列 API 名称。

格式：`Sink类型 | 文件:行号 | 调用符号 | 输入参数 | 可能来源 | 备注`。

### 7. 应审文件列表与 Tier 分类

输出：

- `audit/phase1/in_scope_files.txt`（覆盖率分母**唯一**来源）
- `audit/phase1/tier_list.json`

Tier 规则：

- T1：Controller/Handler/路由/Filter/Interceptor/SecurityConfig/Gateway/MQ consumer/CLI/Job
- T2：Service/DAO/Mapper/Repository/配置/模板/中间件封装
- T3：DTO/Entity/VO/Model/常量/纯类型定义
- 跳过：第三方库、生成代码、构建输出；跳过必须写原因

未匹配文件保守归为 T2。

**测试代码处理**：测试文件不计入 `in_scope_files.txt` 覆盖率分母，但**不完全忽略**。对测试目录做以下有限扫描：
- 搜索硬编码凭证（密码、API Key、连接串、JWT Secret）→ 发现则记入 `secret_inventory.md`
- 搜索测试端点/路由注册 → 检查是否可能泄漏到生产环境（通过 profile/配置开关）
- 搜索集成测试中暴露的架构信息 → 提供给 Phase 2 作为攻击面线索

### 8. 审计形态判定

若同时存在源码和编译产物（`.war / .jar / .class / .dll` 等），必须确定审计形态：

- `source_only`：仅审源码
- `compiled_only`：仅审编译产物（须在阶段 0 完成反编译，见 `shared/decompilation.md`）
- `both`：两者都审

**无法判断时必须询问用户**，不得猜测。

反编译产物审计注意事项（形态 = `compiled_only` 或 `both`）：

- `in_scope_files.txt` 基于反编译输出路径枚举
- Java：`WEB-INF/classes/` 全量反编译（含开发者覆盖类），`WEB-INF/lib/` 仅反编译业务 JAR
- ASP.NET：非 DLL 文件（`.cshtml` / `.aspx` / `.config`）直接纳入
- 反编译代码变量名可能丢失、行号与原始源码不一致；Spring 注解 / ASP.NET 特性通常保留，可正常识别 Controller
- 配置文件（XML/properties/yaml/json/config）在解压产物中存在时直接纳入分析，无需反编译

### 9. OWASP 覆盖矩阵初始化

按 `shared/coverage_matrix_template.md` 输出 `audit/phase1/coverage_matrix.md`，至少覆盖：

- 认证、会话、访问控制、输入验证、文件、SSRF、反序列化、配置、依赖、密钥、业务逻辑
- 每个域标注 ASVS / WSTG / Top10 / CWE、适用性、目标文件 / 入口、当前状态、限制

## 输出

| 文件 | 说明 |
|------|------|
| `audit/phase1/phase1_recon.md` | 技术栈、框架、审计形态简报 |
| `audit/phase1/project_inventory.json` | 项目画像结构化数据 |
| `audit/phase1/architecture_inventory.md` | 架构、模块、数据流、信任边界 |
| `audit/phase1/auth_model.md` | 认证、授权、租户、拦截链 |
| `audit/phase1/framework_authz_map.md` | 框架级鉴权/授权专项清单 |
| `audit/phase1/dependency_list.json` | 依赖、版本、供应链和 gadget 线索 |
| `audit/phase1/secret_inventory.md` | 硬编码账号、密码、密钥、Token、连接串、证书 |
| `audit/phase1/endpoint_list.md` | 全部入口 |
| `audit/phase1/sink_list.md` | 危险 API 和敏感能力 |
| `audit/phase1/in_scope_files.txt` | 覆盖率分母 |
| `audit/phase1/tier_list.json` | 文件 Tier 分类 |
| `audit/phase1/known_system_intel.md` | 已知系统历史漏洞情报（非已知系统时写空） |
| `audit/phase1/coverage_matrix.md` | OWASP/ASVS/WSTG/CWE 覆盖矩阵 |
