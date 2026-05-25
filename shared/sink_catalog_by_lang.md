# 各语言危险 Sink 速查表

> 何时不需要读：模型对 `Runtime.exec / eval / pickle.loads / yaml.load` 等常识 sink 的预训练浓度极高；当审计目标语言是 Java/Python/Go/Node.js/PHP/.NET 主流语言时，子 skill 主体只需提示"按域审"，无需重复罗列；只有遇到陌生框架、希望对照"沉睡知识抽屉"、或新增非主流语言时才读本文档。
>
> 此文档充当 audit-recon、audit-sink、audit-validate 的语言级 Sink 索引；按"维度 → 语言 → 典型 API"组织，可被增量扩展而无须改 SKILL 主体。

## D1 注入（含命令/SQL/SSTI/LDAP/XPath）

| 语言 | 典型 sink |
|------|-----------|
| Java | `Runtime.exec`、`ProcessBuilder`、字符串拼接 SQL（`Statement.executeQuery`）、`SpelExpressionParser`、`Velocity.evaluate`、`FreemarkerTemplate.process`、动态 `OGNL`、`MessageFormat.format` + SQL |
| Python | `os.system`、`subprocess.run(... shell=True)`、`eval`、`exec`、`render_template_string`（Jinja2 SSTI）、raw SQL via `cursor.execute(f"... {x}")`、`ldap.search` 字符串拼接 |
| Go | `os/exec.Command(string)` + 拼接、`database/sql.Query` 字符串拼接、`text/template` 用户控制模板源、`html/template` 含 raw 转义绕过 |
| Node.js | `eval`、`child_process.exec`、`vm.runInContext`、ORM raw query（`sequelize.query`/`knex.raw`）、`Handlebars.compile(userInput)` |
| PHP | `system`、`exec`、`shell_exec`、`eval`、`assert`、`call_user_func` + 用户输入、`mysqli_query` 字符串拼接 |
| .NET | `Process.Start`、`SqlCommand.CommandText` 字符串拼接、`string.Format` + SQL、`DataTable.Select` + 拼接、`Razor` `@Html.Raw` |

## D4 反序列化

| 语言 | 典型 sink |
|------|-----------|
| Java | `ObjectInputStream.readObject`、`Fastjson` `JSON.parseObject(s, Object.class)`、`Jackson` 多态 `enableDefaultTyping`、`XStream.fromXML`、`SnakeYAML.load`、`LosFormatter`、缓存/MQ 反序列化（Redis/Memcached/RabbitMQ key 反序列化） |
| Python | `pickle.loads`、`yaml.load`（无 `SafeLoader`）、`marshal.loads`、`shelve.open` |
| PHP | `unserialize`、`__wakeup` gadget、`phar://` 反序列化 |
| .NET | `BinaryFormatter.Deserialize`、`SoapFormatter`、`NetDataContractSerializer`、`LosFormatter`、`ObjectStateFormatter`（ViewState）、`Json.Net` `TypeNameHandling != None` |

## D5 文件操作

| 语言 | 典型 sink |
|------|-----------|
| Java | `Files.write(... + userPath)`、`FileInputStream(userPath)`、`ZipEntry.getName` 解压未校验（zip-slip）、`MultipartFile.transferTo` 路径未规范化 |
| Python | `open(userPath)`、`shutil.copy(... + user)`、`zipfile.extract` 未校验、`tarfile.extract` |
| Go | `os.Open`/`os.Create` + `filepath.Join(base, userPath)` 未 `filepath.Clean`、`archive/zip` 解压未校验 |
| Node.js | `fs.readFile(userPath)`、`fs.createReadStream`、`path.resolve(base, userPath)` 未限制、解压库 |
| PHP | `file_get_contents`、`include`/`require` 动态路径、`fopen` |
| .NET | `File.ReadAllBytes(userPath)`、`Path.Combine(base, user)` 未规范化、`ZipFile.ExtractToDirectory` 未校验 |

## D6 SSRF

| 语言 | 典型 sink |
|------|-----------|
| Java | `URL.openConnection`、`HttpClient.send`、`OkHttp`、`RestTemplate`、`WebClient.get`、图片/文档转换库 |
| Python | `requests.get(userUrl)`、`urllib.urlopen`、`httpx`、PDF/Office 渲染库 |
| Go | `http.Get`、`http.NewRequest`、`httputil.NewSingleHostReverseProxy` |
| Node.js | `fetch`、`axios`、`http.request`、`request` |
| PHP | `file_get_contents` 远程 URL、`curl_exec`、`fopen` 远程 |
| .NET | `HttpClient.GetAsync`、`WebRequest.Create`、`HttpWebRequest` |

## D7 加密 / 凭据

跨语言通用：`MD5`/`SHA1` 用于密码、固定 salt、`Random` 用于安全场景（应 `SecureRandom`）、硬编码 API key/JWT secret、禁用证书校验（`TrustAllManager` / `verify=False` / `InsecureSkipVerify: true`）。

## D8 模板 / 表达式

| 引擎 | 典型注入 sink |
|------|--------------|
| Spring SpEL | `SpelExpressionParser.parseExpression(userInput)` |
| Struts2 OGNL | `%{userInput}` 形式 |
| Velocity | `Velocity.evaluate(ctx, sw, "", userInput)` |
| FreeMarker | `Template.process(... userInput as 模板源)` |
| Jinja2 | `render_template_string(userInput)` |
| Handlebars | `Handlebars.compile(userInput)` |
| Twig (PHP) | `Twig\Loader\ArrayLoader([... user ...])` |

## A06 供应链已知高危组件（无版本则需结合 dependency_list 复核）

| 组件 | 高危版本/特征 |
|------|--------------|
| Fastjson | < 1.2.83；autoType 默认开 / safeMode 未启 |
| XStream | < 1.4.18；无类型白名单 |
| Jackson | `enableDefaultTyping` 启用 + 老版本 |
| Log4j | 2.0–2.16；启用 lookup（CVE-2021-44228） |
| Struts2 | OGNL 解析路径暴露（多 CVE） |
| Spring Cloud Gateway | < 3.1.1 actuator 表达式注入（CVE-2022-22947） |
| commons-collections | 3.x、4.0 用于 readObject gadget |
| Apache Commons Text | < 1.10 StringSubstitutor lookup（CVE-2022-42889） |

## 使用规范

- audit-recon 在 Phase 1 输出 `sink_list.md` 时，按域引用本表，无需复述完整 API 名。
- audit-sink 在 Phase 2 追踪 source-to-sink 时，仅在遇到本表外的非常规 sink 时才需在 SKILL.md 主体内描述细节。
- audit-validate 在 Phase 4 复核反序列化/RCE 候选时，按依赖版本 + 本表"A06 高危组件"快表交叉判断。
- 新增语言或 sink 时，**只追加到本文件**，不要回写到子 SKILL 主体。

## 遇到本表外 sink 时（联网兜底）

本表覆盖主流；冷门 sink、CVE 驱动新 sink、新框架 API 永远列不完。遇到本表外 sink 时按 `shared/external_knowledge_protocol.md` §2 表 #1/#6 联网查官方语义 + 公开 CVE；查询结果必须按 §4 格式留 URL 写入 finding 的「外部依据」字段。**禁止编造 sink 危险性。**

## applicability（模型代际标签）

| 内容块 | 模型预训练覆盖度 | 何时可裁剪 |
|--------|----------------|----------|
| D1 命令/SQL/SSTI 主流 sink | 高（claude-4.x / gpt-5.x 全部已知） | 模型 V5+ 后可削减一半 |
| D4 反序列化主流 sink | 高 | 模型 V5+ 后可削减一半 |
| D5/D6/D7 主流 sink | 高 | 同上 |
| D8 模板/表达式引擎 | 中（小众引擎模型不熟） | 长期保留 |
| A06 高危组件表 | **低**（CVE 持续涌现） → **必须长期保留 + 联网兜底** | 永远必要 |
| .NET 专项 sink（如 `LosFormatter`、`QueryOptions.Where`） | 中（模型对 .NET 浓度不如 Java/Python） | 长期保留 |

遇到不在表内的项 → 按 `shared/external_knowledge_protocol.md` 联网查询，不要回填到本表。

## 前端安全审计要点（前后端一体项目适用）

审计前后端一体项目（Next.js/Nuxt/SvelteKit 等）或包含前端代码的项目时，以下前端 sink 也需纳入审计：

| 类型 | 危险 API/模式 | 说明 |
|------|-------------|------|
| DOM XSS | `innerHTML`、`outerHTML`、`document.write`、`insertAdjacentHTML` | 用户输入直接写入 DOM |
| React | `dangerouslySetInnerHTML` | React 唯一的 XSS 入口 |
| Vue | `v-html` | Vue 的非转义输出 |
| Angular | `bypassSecurityTrustHtml/Url/Script` | 绕过 Angular 安全机制 |
| eval 类 | `eval()`、`new Function()`、`setTimeout(string)` | 客户端代码执行 |
| postMessage | `window.addEventListener('message', ...)` 无 origin 校验 | 跨域消息伪造 |
| 原型污染 | `Object.assign(target, userInput)`、深合并库 | 客户端原型链污染 |
| WebSocket | 无认证/无 origin 校验的 WebSocket 端点 | 未授权数据推送/注入 |
| URL 跳转 | `window.location = userInput`、`window.open(userInput)` | 开放重定向/钓鱼 |

## GraphQL 专项审计要点

| 检查项 | 说明 |
|--------|------|
| Introspection | 生产环境是否禁用 `__schema`/`__type` 查询 |
| 深度限制 | 是否有 query depth limit 防嵌套查询 DoS |
| 字段级授权 | 是否每个 resolver/field 都有权限检查（不只是 endpoint 级） |
| Batching | 是否允许 query batching（绕过限流/CSRF） |
| Mutation 注入 | Mutation 的 input 参数是否存在 SQL/NoSQL 注入 |
| N+1 信息泄露 | 通过 relationship 遍历是否可越权访问关联数据 |

## gRPC 专项审计要点

| 检查项 | 说明 |
|--------|------|
| 认证 | 是否使用 TLS + per-RPC credentials（非明文传输） |
| 授权 | 是否有 interceptor/middleware 做权限检查 |
| 反序列化 | Protobuf 本身安全，但自定义 codec/序列化器可能不安全 |
| 反射服务 | gRPC Server Reflection 是否在生产开启（泄露接口定义） |
| 大消息 | 是否设置 maxReceiveMessageSize 防大消息攻击 |
