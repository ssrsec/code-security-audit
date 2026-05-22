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

### 3. 依赖、Secret 与供应链画像

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

### 4. 入口枚举

输出 `audit/phase1/endpoint_list.md`，覆盖：

- HTTP API、页面路由、WebSocket、GraphQL、gRPC、RPC、MQ consumer、CLI、定时任务、文件导入
- 必审入口关键词：`login / register / oauth / sso / callback / admin / role / permission / tenant / export / download / upload / payment / delete / reset / debug / internal / actuator`
- 格式：`HTTP方法 | 路径 | Handler文件:行号 | 是否需认证 | 权限要求 | 资产/风险`

### 5. Sink 与危险能力枚举

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

### 6. 应审文件列表与 Tier 分类

输出：

- `audit/phase1/in_scope_files.txt`（覆盖率分母**唯一**来源）
- `audit/phase1/tier_list.json`

Tier 规则：

- T1：Controller/Handler/路由/Filter/Interceptor/SecurityConfig/Gateway/MQ consumer/CLI/Job
- T2：Service/DAO/Mapper/Repository/配置/模板/中间件封装
- T3：DTO/Entity/VO/Model/常量/纯类型定义
- 跳过：第三方库、生成代码、构建输出、测试样例；跳过必须写原因

未匹配文件保守归为 T2。

### 7. 审计形态判定

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

### 8. OWASP 覆盖矩阵初始化

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
| `audit/phase1/coverage_matrix.md` | OWASP/ASVS/WSTG/CWE 覆盖矩阵 |
