---
name: audit-recon
description: 阶段 1 白盒审计侦察。由 audit-orchestrator 在 Phase 1 调度，执行技术栈识别、入口枚举、Tier 分类（T1/T2/T3）、覆盖矩阵初始化、应审文件列表生成、危险 Sink 清单整理，同时输出项目画像、架构信息、认证授权模型和依赖列表。当用户说「开始侦察」「识别技术栈」「枚举端点」，或 audit-orchestrator 进入 Phase 1 时触发。
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

常见框架识别（按语言）：
- **Java**：Spring Boot、Struts、MyBatis、Hibernate、Fastjson、Jackson、Log4j
- **Python**：Django、Flask、FastAPI、SQLAlchemy、Jinja2、PyYAML
- **Go**：Gin、Echo、GORM、net/http
- **Node.js**：Express、NestJS、Sequelize、TypeORM、Handlebars、Pug
- **PHP**：Laravel、ThinkPHP、CodeIgniter
- **.NET**：ASP.NET Core、ASP.NET MVC

输出到 `audit/phase1/project_inventory.json` 和 `audit/phase1/architecture_inventory.md`。

### 2. 认证与授权模型

必须按 `shared/framework_authz_checklist.md` 单独分析并输出 `audit/phase1/auth_model.md` 与 `audit/phase1/framework_authz_map.md`：

- 登录、注册、找回密码、SSO/OAuth/OIDC、回调入口。
- session/JWT/API key/cookie/header 的存储位置、生命周期和刷新逻辑。
- 全局 Filter/Interceptor/Middleware/Gateway/SecurityConfig。
- RBAC/ABAC/ACL/自定义权限模型。
- 资源归属校验、租户隔离、管理员权限边界。
- 白名单、匿名接口、内部接口、调试接口。
- 框架专项：Spring Security、Shiro、Sa-Token、RuoYi/Jeecg、Django DRF、NestJS Guard、Laravel Middleware、ASP.NET Authorization 等。

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
- 格式：`HTTP方法 | 路径 | Handler文件:行号 | 是否需认证 | 权限要求 | 资产/风险`。

### 5. Sink 与危险能力枚举

输出 `audit/phase1/sink_list.md`，覆盖：

- 命令执行、模板/表达式执行、反序列化、动态代码执行。
- SQL/NoSQL/LDAP/XPath/ORM raw query。
- SSRF/URL fetch/代理/回调。
- 文件上传、下载、读取、写入、解压。
- 加解密、签名、JWT、随机数、密码哈希。
- 权限变更、角色分配、租户切换、高价值数据导出。

常见 Sink 按语言：
- **Java**：`Runtime.exec()`、`ProcessBuilder`、`InitialContext.lookup()`（JNDI）、`ObjectInputStream.readObject()`、`JSON.parseObject()`（Fastjson）、`SpelExpressionParser`、字符串拼接的 SQL
- **Python**：`eval()`、`exec()`、`os.system()`、`subprocess`、`pickle.loads()`、`yaml.load()`、`render_template_string()`（SSTI）
- **Go**：`os/exec.Command()`、`text/template`（SSTI）、`database/sql` 字符串拼接、`http.Get()`（SSRF）
- **Node.js**：`eval()`、`child_process.exec()`、`vm.runInContext()`、`fs.readFile()` 动态路径、原型污染
- **PHP**：`system()`、`exec()`、`eval()`、`unserialize()`、`include()`/`require()` 动态路径

格式：`Sink类型 | 文件:行号 | 调用符号 | 输入参数 | 可能来源 | 备注`。

### 6. 应审文件列表与 Tier 分类

输出：

- `audit/phase1/in_scope_files.txt`（此列表为覆盖率分母唯一来源）
- `audit/phase1/tier_list.json`

Tier 规则：

- T1：Controller/Handler/路由/Filter/Interceptor/SecurityConfig/Gateway/MQ consumer/CLI/Job。
- T2：Service/DAO/Mapper/Repository/配置/模板/中间件封装。
- T3：DTO/Entity/VO/Model/常量/纯类型定义。
- 跳过：第三方库、生成代码、构建输出、测试样例；跳过必须写原因。

未匹配文件保守归为 T2。

### 7. 审计形态判定

若同时存在源码和编译产物（.war/.jar/.class/.dll 等），必须确定审计形态：
- `source_only`：仅审计源码
- `compiled_only`：仅审计编译产物（须在阶段 0 完成反编译，见 `shared/decompilation.md`）
- `both`：两者都审

**无法判断时必须询问用户**，不得猜测。

**反编译产物审计注意事项**（当审计形态为 `compiled_only` 或 `both` 时）：
- `in_scope_files.txt` 基于反编译输出路径枚举，包含所有反编译后的业务代码文件。
- 对于 Java：`WEB-INF/classes/` 全量反编译（含开发者覆盖类），`WEB-INF/lib/` 仅反编译业务 JAR；对于 ASP.NET：非 DLL 文件（`.cshtml`/`.aspx`/`.config`）直接纳入审计范围。
- 反编译代码的变量名可能丢失、行号与原始源码不一致，Tier 分类和端点识别需适配（Spring 注解/ASP.NET 特性通常保留，可正常识别 Controller）。
- 配置文件（XML/properties/yaml/json/config）若在解压产物中存在，应直接纳入分析，无需反编译。

### 8. OWASP 覆盖矩阵初始化

按 `shared/coverage_matrix_template.md` 输出 `audit/phase1/coverage_matrix.md`，至少覆盖：

- 认证、会话、访问控制、输入验证、文件、SSRF、反序列化、配置、依赖、密钥、业务逻辑。
- 每个域标注 ASVS/WSTG/Top10/CWE、适用性、目标文件/入口、当前状态和限制。

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
