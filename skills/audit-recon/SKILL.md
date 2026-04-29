---
name: audit-recon
description: 阶段 1 白盒审计侦察。输出项目画像、架构信息、认证授权模型、入口、sink、依赖、覆盖矩阵和应审文件列表。
---

# 审计侦察（阶段 1）

## 角色

负责阶段 1：建立项目基础架构画像和攻击面地图。此阶段不做漏洞定性，只收集可验证事实，为阶段 2-4 提供覆盖分母、入口、sink、鉴权模型、依赖版本和标准覆盖矩阵。

## 输入

- 阶段 0 的 `metrics.md`、`scope.md`。
- 项目根路径。
- 反编译输出路径（如存在）。

## 执行步骤

### 1. 项目结构与技术栈识别

用 `rg --files`、`find`、构建文件和配置文件识别：

- 开发语言、版本、主要目录。
- 框架：Spring/Struts/Django/FastAPI/Express/NestJS/Laravel/ASP.NET/Gin 等。
- 构建系统：Maven/Gradle/npm/pnpm/yarn/pip/poetry/go mod/composer/dotnet。
- 运行方式：单体、前后端分离、微服务、Serverless、CLI、定时任务。
- 中间件：数据库、缓存、MQ、搜索、对象存储、任务队列。

输出到 `audit/phase1/project_inventory.json` 和 `audit/phase1/architecture_inventory.md`。

### 2. 认证与授权模型

必须按 `shared/framework_authz_checklist.md` 单独分析并输出 `audit/phase1/auth_model.md` 与 `audit/phase1/framework_authz_map.md`：

- 登录、注册、找回密码、SSO/OAuth/OIDC、回调入口。
- session/JWT/API key/cookie/header 的存储位置、生命周期和刷新逻辑。
- 全局 Filter/Interceptor/Middleware/Gateway/SecurityConfig。
- RBAC/ABAC/ACL/自定义权限模型。
- 资源归属校验、租户隔离、管理员权限边界。
- 白名单、匿名接口、内部接口、调试接口。
- 框架专项：Spring Security、Shiro、Sa-Token、RuoYi/Jeecg、Django DRF、NestJS Guard、Laravel Middleware、ASP.NET Authorization 等项目实际使用框架。

无法确认时写入 `unknowns`，不得猜测。

### 3. 依赖、Secret 与供应链画像

输出 `audit/phase1/dependency_list.json`：

- 直接依赖和锁定版本。
- 已知高危组件线索：Fastjson、XStream、Jackson polymorphic、Log4j、Struts、Spring Cloud Gateway、模板引擎、反序列化库。
- Java classpath / `WEB-INF/lib` / `lib` / `node_modules` / `vendor` 中可能作为 gadget 的依赖。
- Secret、私有 registry、脚本安装钩子、postinstall 等供应链线索。

按 `shared/secret_detection.md` 输出 `audit/phase1/secret_inventory.md`：

- 硬编码账号、密码、API key、JWT secret、数据库/Redis/MQ 连接串、私钥、证书、云厂商 AK/SK。
- 标记来源文件:行号、加载 profile、是否生产可达、是否已脱敏、验证等级。
- 明显示例值或不可达测试值必须记录排除理由。

### 4. 入口枚举

输出 `audit/phase1/endpoint_list.md`，覆盖：

- HTTP API、页面路由、WebSocket、GraphQL、gRPC、RPC、MQ consumer、CLI、定时任务、文件导入。
- 必审入口：login、register、oauth、sso、callback、admin、role、permission、tenant、export、download、upload、payment、delete、reset、debug、internal、actuator。
- 格式：`入口类型 | 方法/Topic/命令 | 路径/名称 | Handler 文件:行号 | 认证要求 | 权限要求 | 资产/风险`。

### 5. Sink 与危险能力枚举

输出 `audit/phase1/sink_list.md`：

- 命令执行、模板/表达式执行、反序列化、动态代码执行。
- SQL/NoSQL/LDAP/XPath/ORM raw query。
- SSRF/URL fetch/代理/回调。
- 文件上传、下载、读取、写入、解压。
- 加解密、签名、JWT、随机数、密码哈希。
- 权限变更、角色分配、租户切换、高价值数据导出。

格式：`Sink类型 | 文件:行号 | 调用符号 | 输入参数 | 可能来源 | 备注`。

### 6. 应审文件列表与 Tier 分类

输出：

- `audit/phase1/in_scope_files.txt`
- `audit/phase1/tier_list.json`

Tier 规则：

- T1：Controller/Handler/路由/Filter/Interceptor/SecurityConfig/Gateway/MQ consumer/CLI/Job。
- T2：Service/DAO/Mapper/Repository/配置/模板/中间件封装。
- T3：DTO/Entity/VO/Model/常量/纯类型定义。
- 跳过：第三方库、生成代码、构建输出、测试样例；跳过必须写原因。

未匹配文件保守归为 T2。

### 7. OWASP 覆盖矩阵初始化

按 `shared/coverage_matrix_template.md` 输出 `audit/phase1/owasp_coverage_matrix.md`，至少覆盖：

- 认证、会话、访问控制、输入验证、文件、SSRF、反序列化、配置、依赖、密钥、业务逻辑。
- 每个域标注 ASVS/WSTG/Top10/CWE、适用性、目标文件/入口、当前状态和限制。

## 输出

| 文件 | 说明 |
|------|------|
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
| `audit/phase1/owasp_coverage_matrix.md` | 标准覆盖矩阵 |
