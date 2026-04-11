---
name: audit-recon
description: 阶段 1 审计侦察。技术栈识别、入口枚举、Tier 分类、覆盖矩阵初始化、应审文件列表、端点清单、Sink 清单。
---

# 审计侦察（阶段 1）

## 角色

负责 阶段 1：识别技术栈、枚举 API 入口、Tier 分类、初始化覆盖矩阵。**不做漏洞判断**，只做信息收集与优先级分层。

## 执行步骤

### 1. 技术栈识别

用 Glob 和 Read 识别项目使用的语言、框架、关键依赖：
- **Java**：Spring Boot、Struts、MyBatis、Hibernate、Fastjson、Jackson、Log4j
- **Python**：Django、Flask、FastAPI、SQLAlchemy、Jinja2、PyYAML
- **Go**：Gin、Echo、GORM、net/http
- **Node.js**：Express、NestJS、Sequelize、TypeORM、Handlebars、Pug
- **PHP**：Laravel、ThinkPHP、CodeIgniter
- **.NET**：ASP.NET Core、ASP.NET MVC

### 2. 生成应审文件列表

- 枚举所有包含业务逻辑的源代码文件。
- 排除：测试目录、生成代码、第三方依赖（node_modules、vendor、target、venv、site-packages 等）。
- 输出到 `audit/phase1/in_scope_files.txt`，**此列表为覆盖率分母唯一来源**。

### 3. 枚举端点（攻击面）

识别所有 API 路由、Web 端点、WebSocket、gRPC handler。**必须包含**：
- **认证相关**：login、register、oauth、sso、callback、signin、auth
- **高价值目标**：export、download、upload、admin、report、payment、delete、reset
- **内部/调试接口**：/actuator/、/debug/、/metrics/、/internal/

输出到 `audit/phase1/endpoint_list.md`，格式：`HTTP方法 | 路径 | Handler文件:行号 | 是否需认证`。

### 4. 识别 Sink（危险 API）

根据技术栈列出代码中存在的危险 API：
- **Java**：`Runtime.exec()`、`ProcessBuilder`、`InitialContext.lookup()`（JNDI）、`ObjectInputStream.readObject()`、`JSON.parseObject()`（Fastjson）、`SpelExpressionParser`、`Velocity.evaluate()`、字符串拼接的 SQL
- **Python**：`eval()`、`exec()`、`os.system()`、`subprocess`、`pickle.loads()`、`yaml.load()`、`render_template_string()`（SSTI）
- **Go**：`os/exec.Command()`、`text/template`（SSTI）、`database/sql` 字符串拼接、`http.Get()`（SSRF）
- **Node.js**：`eval()`、`child_process.exec()`、`vm.runInContext()`、`fs.readFile()` 动态路径、原型污染（Object.assign、深合并）
- **PHP**：`system()`、`exec()`、`eval()`、`unserialize()`、`include()`/`require()` 动态路径

输出到 `audit/phase1/sink_list.md`，格式：`Sink类型 | 文件:行号 | 上下文`。

### 5. Tier 分类

- **T1（入口层）**：Controller/Handler/路由/Filter/Interceptor/SecurityConfig → 完整深度分析
- **T2（业务层）**：Service/DAO/Mapper/中间件/配置文件 → 先筛后读
- **T3（数据层）**：Entity/VO/DTO/Model → 模式匹配
- **跳过**：第三方库源码、测试代码

未匹配的保守归为 T2。

### 6. 审计形态判定

若同时存在源码和编译产物（.war/.jar/.class/.dll 等），必须确定审计形态：
- `source_only`：仅审计源码
- `compiled_only`：仅审计编译产物（须在 阶段 0 完成反编译，见 `shared/decompilation.md`）
- `both`：两者都审

**无法判断时必须询问用户**，不得猜测。

**反编译产物审计注意事项**（当审计形态为 `compiled_only` 或 `both` 时）：
- `in_scope_files.txt` 基于反编译输出路径枚举，包含所有反编译后的业务代码文件
- 对于 Java：`WEB-INF/classes/` 全量反编译（含开发者覆盖类），`WEB-INF/lib/` 仅反编译业务 JAR；对于 ASP.NET：非 DLL 文件（`.cshtml`/`.aspx`/`.config`）直接纳入审计范围
- 反编译代码的变量名可能丢失、行号与原始源码不一致，Tier 分类和端点识别需适配（如 Spring 注解 / ASP.NET 特性通常保留，可正常识别 Controller）
- 配置文件（XML/properties/yaml/json/config）若在解压产物中存在，应直接纳入分析，无需反编译

## 输出

| 文件 | 说明 |
|------|------|
| `audit/phase1/phase1_recon.md` | 技术栈、框架、审计形态 |
| `audit/phase1/in_scope_files.txt` | 应审文件列表（覆盖率分母） |
| `audit/phase1/tier_list.json` | Tier 分类 |
| `audit/phase1/coverage_matrix.md` | 覆盖矩阵 |
| `audit/phase1/endpoint_list.md` | 端点清单 |
| `audit/phase1/sink_list.md` | 危险 API 清单 |
| `audit/phase1/dependency_list.json` | 依赖清单 |
