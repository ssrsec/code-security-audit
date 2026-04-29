# 框架级认证与授权检查清单

本文件用于阶段 1-4 对常见框架的认证、授权、租户隔离和资源归属进行专项检查。目标是避免只看业务代码，漏掉框架默认策略、注解语义、拦截器顺序和路由匹配问题。

## 1. 通用检查

- 找到全局认证入口：Filter、Interceptor、Middleware、Guard、Policy、Gateway。
- 找到授权入口：角色注解、权限表达式、ACL、策略函数、权限表、租户过滤器。
- 枚举白名单和匿名路由，确认默认策略是 deny-by-default 还是 allow-by-default。
- 对端点清单与权限配置做 diff，找未登记、误登记、路径匹配过宽或顺序错误。
- 区分认证、授权、租户隔离：已登录不等于有资源权限，跳过租户不等于匿名访问。

## 2. Java / Spring Security

- 检查 `SecurityFilterChain`、`WebSecurityConfigurerAdapter`、`authorizeHttpRequests`、`antMatchers`、`requestMatchers`。
- 检查 `permitAll`、`anonymous`、`ignoring`、`csrf().disable()` 的实际影响。
- 检查 `@PreAuthorize`、`@PostAuthorize`、`@Secured`、自定义权限注解是否被启用。
- 注意路径匹配顺序：宽路径在前可能覆盖窄路径。
- 检查 method security 是否开启，否则方法级注解可能无效。

## 3. Java / Apache Shiro

- 检查 `shiroFilterFactoryBean`、filter chain definition、`anon`、`authc`、`roles`、`perms`。
- 检查链顺序，`/** = anon` 或过宽 anon 会导致绕过。
- 检查 RememberMe、默认密钥、历史反序列化风险。
- 检查权限字符串是否与业务接口一致。

## 4. Java / Sa-Token

- 检查路由拦截器、`SaRouter.match`、`notMatch`、`StpUtil.checkLogin/checkPermission/checkRole`。
- 检查 `@SaIgnore`、白名单、后台管理路径。
- 检查是否只检查登录，不检查角色/权限/租户。

## 5. RuoYi / Jeecg / 常见后台框架

- 检查 Controller 上 `@PreAuthorize` 或框架权限注解是否与菜单/权限表一致。
- 检查导出、下载、详情、删除、批量操作是否缺少权限注解。
- 检查数据权限注解、部门/租户过滤是否只用于列表而遗漏详情/导出。
- 检查 Swagger、Druid、Actuator、文件预览、在线表单、代码生成器接口。

## 6. Python / Django / DRF

- 检查 `DEFAULT_PERMISSION_CLASSES`、ViewSet `permission_classes`、`@permission_classes`。
- 检查 `AllowAny` 是否仅用于登录/公开接口。
- 检查 object-level permission：`get_queryset` 是否按 owner/tenant 过滤，`get_object` 是否绕过。
- 检查 admin、自定义 action、导出接口、批量接口是否单独授权。

## 7. Node.js / Express / NestJS

- Express/Koa：检查 middleware 注册顺序、路由前缀、`next()` 分支、公开 static。
- NestJS：检查 `Guards`、`@UseGuards`、`@Public`、`Reflector`、全局 guard 是否启用。
- 检查 controller 级 guard 是否覆盖 method 级公开装饰器。
- 检查 GraphQL resolver 是否复用 REST 鉴权逻辑。

## 8. PHP / Laravel

- 检查 `routes/web.php`、`routes/api.php` 中 middleware 分组。
- 检查 `auth`、`can`、Policy、Gate、FormRequest authorize。
- 检查 route model binding 是否校验 owner/tenant。
- 检查 admin route、导出、文件下载、队列任务、调试路由。

## 9. .NET / ASP.NET Core

- 检查 `UseAuthentication` 与 `UseAuthorization` 顺序。
- 检查 `[AllowAnonymous]`、`[Authorize]`、policy、role、claims。
- 检查 endpoint routing 是否对所有 controller/map endpoint 生效。
- 检查 resource-based authorization 是否用于对象级访问控制。

## 10. 验证要求

- 每个疑似鉴权/越权 finding 必须给出框架层证据：配置、注解、中间件、权限表或拦截器路径。
- 必须设计权限对照请求：无认证、低权限、目标权限。
- 如果框架配置不可见或运行 profile 不确定，标 V1 待验证，不得直接标已确认。
