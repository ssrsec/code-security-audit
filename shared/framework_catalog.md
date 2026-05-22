# 各语言主流框架与中间件速查表

> 何时不需要读：模型对 Spring/Express/Django/Laravel 等主流 Web 框架的预训练浓度极高；当 audit-recon 在 Phase 1 识别技术栈时，主流框架可由模型自动给出。只有遇到陌生框架、需要对照"框架别名 / 内部封装函数 / 默认 Sink"时才读本文档。
>
> 此文档与 `framework_authz_checklist.md`（鉴权专项）正交：本表覆盖"框架是什么 / 入口与 ORM 长什么样"，鉴权 checklist 覆盖"权限模型怎么校"。

## Web 框架

| 语言 | 框架 | Controller 标识 | 路由声明 | ORM/DAO |
|------|------|----------------|----------|---------|
| Java | Spring Boot | `@Controller` / `@RestController` | `@RequestMapping` 系列 | MyBatis (`@Mapper`)、JPA、JdbcTemplate |
| Java | Struts2 | extends `Action` | `struts.xml` / `@Action` | DAO 自定义 |
| Python | Django | `views.py` 函数/类 | `urls.py` `path()` | Django ORM (`QuerySet`)、`django.db.connection.cursor` raw |
| Python | Flask | `@app.route` | 函数装饰器 | SQLAlchemy、`cursor.execute` raw |
| Python | FastAPI | `@app.get`/`@router.post` | 函数装饰器 | SQLAlchemy、Tortoise |
| Go | Gin | `r.GET/POST` 处理函数 | 路由树 | GORM、`database/sql` |
| Go | Echo | `e.GET` | 同上 | 同上 |
| Node.js | Express | `app.get/post` 处理函数 | router 链 | Sequelize、TypeORM、Prisma、`knex` |
| Node.js | NestJS | `@Controller` + `@Get`/`@Post` | 装饰器 + 模块化 | TypeORM、Prisma、Mongoose |
| PHP | Laravel | `Controllers/*Controller.php` | `routes/web.php`/`api.php` | Eloquent、Query Builder |
| PHP | ThinkPHP | `app/controller/*Controller.php` | 路由配置 | think-orm |
| .NET | ASP.NET Core | `Controllers/*Controller.cs` + `[ApiController]` | `[Route]`/`[Http*]` | EF Core、Dapper |
| .NET | ASP.NET MVC | `Controllers/*Controller.cs` | `RouteConfig` | EF、ADO.NET |

## 模板/视图引擎

| 引擎 | 转义默认 | 危险出口（XSS 风险） |
|------|---------|---------------------|
| Thymeleaf (Java) | 转义 | `th:utext`、`th:href` 含 javascript: |
| FreeMarker (Java) | 转义 | `<#noescape>`、`?no_esc` |
| Jinja2 (Python) | 转义 | `{{ x|safe }}`、`autoescape=False` |
| Django Template | 转义 | `{{ x|safe }}`、`{% autoescape off %}` |
| Handlebars | 转义 | `{{{ x }}}`（三花括号） |
| Pug / EJS | 默认 raw 或转义视配置 | EJS `<%- %>`、Pug `!= ` |
| Razor (.NET) | 转义 | `@Html.Raw` |
| React JSX | 转义 | `dangerouslySetInnerHTML` |
| Vue | 转义 | `v-html` |

## 中间件 / 反序列化高风险点

| 中间件 | 风险点 |
|--------|-------|
| Redis | 序列化/反序列化策略（Spring `RedisTemplate.setValueSerializer` 用 `JdkSerializationRedisSerializer` 时反序列化 sink） |
| Kafka / RabbitMQ | Java consumer 默认 ObjectInputStream 反序列化 |
| Elasticsearch | 早期 Java HTTP 客户端反序列化漏洞 |
| Memcached | 客户端反序列化策略 |
| Quartz / xxl-job / elastic-job | 定时任务输入污染 |

## 鉴权框架（与 `framework_authz_checklist.md` 配合）

| 框架 | 注解/拦截入口 | 常见绕过线索 |
|------|--------------|--------------|
| Spring Security | `SecurityConfig.configure(HttpSecurity)`、`@PreAuthorize` | `permitAll()` 范围、antMatcher 大小写/尾斜杠 |
| Shiro | `ShiroFilterFactoryBean.filterChainDefinitionMap` | `anon` 范围、过滤器顺序、`/**` 覆盖 |
| Sa-Token | `SaInterceptor` / `@SaCheckLogin` | `SaIgnore` 标记的接口、白名单路径 |
| RuoYi / Jeecg | 框架内置 Filter | 内置 `/system/test/*`、`/test/*` 等遗留路径 |
| DRF (Django) | `permission_classes` | 默认 `AllowAny`、`@api_view` 单独覆盖 |
| NestJS Guard | `@UseGuards(AuthGuard)` | `@Public()` 装饰、全局 Guard 注册位置 |
| Laravel Middleware | `Route::middleware('auth')` | 路由组遗漏、`api` 与 `web` 中间件差异 |
| ASP.NET Authorization | `[Authorize]` | `[AllowAnonymous]` 覆盖、Filter pipeline 顺序 |

## 使用规范

- audit-recon 在 Phase 1 识别技术栈与认证模型时，主流框架可直接判定；遇到本表外或定制框架时，按"通用模式 + 写入 unknowns"处理。
- audit-control 在 Phase 2 鉴权审计时，本表 + `framework_authz_checklist.md` 配合使用。
- 新增框架或鉴权方案时，**只追加到本文件**或 `framework_authz_checklist.md`，不要回写到子 SKILL 主体。

## 遇到本表外框架时（联网兜底）

按 `shared/external_knowledge_protocol.md` §2 表 #1 查框架官方 doc 与默认安全行为；必须留 URL 写入 finding 的「外部依据」字段。**禁止凭印象编造框架的鉴权 API 名称或默认行为。**

## applicability（模型代际标签）

| 内容块 | 模型预训练覆盖度 | 何时可裁剪 |
|--------|----------------|----------|
| Web 主流框架（Spring/Express/Django/Laravel） | 高 | 模型 V5+ 后可大幅裁剪 |
| 模板引擎转义行为 | 中（多数模型懂主流） | 长期保留（小众模板易遗漏） |
| 中间件反序列化高风险点 | **低**（Redis/Kafka/Quartz 反序列化策略与版本强相关） → **必须保留 + 联网兜底** | 永远必要 |
| 鉴权框架绕过线索 | **低**（每个框架特有的 `permitAll / @SaIgnore / SaIgnore` 绕过形式） → **必须保留** | 长期保留 |

新框架的绕过模式应追加到本表，不要回填到子 SKILL 主体。
