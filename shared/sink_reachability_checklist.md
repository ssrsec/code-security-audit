# Sink 可达性检查清单（reachability）

> **何时必读**：audit-sink 在 Phase 2 报候选前；audit-validate 在 Phase 4 把"代码线索" 升格为"已确认"或"待验证"前。
> **何时不需要读**：已经手握运行时 PoC 证据（V3/V4 已确认）的漏洞 —— 此时可达性已被实战验证。
>
> 本文档规定"sink 是否被调用、过滤是否到位、请求是否可达"的 7 步可执行算法。"sink 函数存在" ≠ "sink 在生产可触发"，必须 7 步全部打勾。

## 1. 7 步可达性算法

每个候选 finding 必须按以下 7 步逐项打勾，任一步未通过 → 至少降为「待验证」并明确缺失项：

### R1. sink 定义存在？

- **检查方式**：`Grep -n "sink_signature" --type lang` + `Read` 函数体
- **通过**：找到方法/函数实际定义，**不是 import 声明 / 注释 / 字符串字面量**
- **常见误判**：把 `// Runtime.exec(cmd)` 注释、把 `String s = "Runtime.exec"` 字符串当成定义
- **失败处理**：丢弃候选

### R2. sink 在被审目录内被实际调用？

- **检查方式**：`Grep -n "sink_function\s*\("` 取得调用点 → `Read` 确认是实际调用而非定义
- **通过**：至少 1 个调用点存在且不在测试/样例目录
- **常见误判**：sink 仅在 unit test 中被调用 / sink 仅在 `@Deprecated` 旧代码中被调用
- **失败处理**：sink 仅定义未调用 → 视证据强度降为「待验证」或「排除」：有间接调用迹象（如反射、动态代理、框架回调）→ 降为「待验证」并注明待确认路径；完全无调用证据 → 排除，写负证据记入 `coverage_matrix.md` 的"已排除"列

### R3. 调用点所在函数/类被生产路径加载？

- **检查方式**：从调用点函数向上追踪所属类 → 检查类是否被注册到生产路由 / Bean / Worker / Job
- **通过条件**：
  - Spring：类有 `@Controller / @RestController / @Component / @Service` 等扫描注解
  - Express/NestJS：类被 `app.use()` / `@Module({controllers: [X]})` 注册
  - Django：类在 `urls.py` 的 `path()` 中
  - 定时任务：类有 `@Scheduled / @Cron` 注解或在 quartz/xxl-job 配置中
- **常见误判**：调用点在 `BaseController` 抽象类中但无具体子类 / 调用点在已被 `@Profile("dev")` 限定的类中
- **失败处理**：未被生产加载 → 排除（写负证据）

### R4. 路由对外可达？

仅适用于 HTTP / WebSocket / GraphQL / gRPC 入口。

- **检查方式**：
  1. 取得 endpoint 路径
  2. 检查 `application.yml / application-{profile}.yml / nginx.conf / ingress.yaml` 中是否被对外暴露
  3. 检查 `@PostConstruct / 启动类配置` 中是否被网关路由排除
- **通过条件**：路径在公网/内网可访问的网关后；或属于明确文档的"开放接口"
- **常见误判**：把 `/actuator/*` 当公开（多数生产被 nginx 拦截）/ 把 `/internal/*` 当不可达（k8s 内部网络可能可达）
- **失败处理**：仅内部 IP 可达 → 标 P3 内部入口，降低 CVSS AV 维度但不丢弃

### R5. 全局拦截器是否覆盖且不可绕过？

仅适用于 Control-driven 类（认证/授权缺失）。

- **检查方式**：
  1. 列出全局 Filter/Interceptor/Middleware/Gateway/SecurityConfig 链
  2. 对每条拦截规则检查路径匹配范围（精确 / 通配 / 前缀）
  3. 检查目标 endpoint 是否在拦截范围内
  4. 检查是否有 `permitAll / @PermitAll / AllowAnonymous / @SaIgnore / @Public` 类排除注解
- **绕过线索**（必查）：
  - 路径前缀大小写不敏感（`/Admin/` vs `/admin/`）
  - 尾斜杠（`/admin` vs `/admin/`）
  - URL 编码（`%2e%2e/` vs `../`）
  - 通配符歧义（`/api/*` 不一定覆盖 `/api/v2/*`）
  - Filter 顺序（鉴权 Filter 在业务 Filter 之后无效）
- **通过条件**：拦截链对目标 endpoint 真实生效，无以上绕过路径
- **失败处理**：发现绕过 → 候选成立；无绕过 → 排除

### R6. source 真正可控？

- **检查方式**：
  1. 追溯 source 的引入路径（HTTP 参数 / Header / Body / 文件内容 / MQ 消息 / DB 二次污染）
  2. 检查 source 是否经过框架强约束（schema validation、类型 binding）
  3. 检查 source 类型是否限制可控范围（`int` vs `String`）
- **通过条件**：source 仍可由攻击者控制（即使经过部分校验仍能构造攻击 payload）
- **常见误判**：把强类型 `@RequestParam int id` 当 SQL 注入 source（数字类对 SQL 注入无效，但对 IDOR/越权仍有效）
- **失败处理**：source 完全不可控 → 排除（写负证据）

### R7. 触发的运行时前提是否满足？

仅适用于条件触发型漏洞（如反序列化需 classpath gadget、SSTI 需特定模板引擎）。

- **检查方式**：
  - 反序列化：Read `pom.xml / build.gradle / requirements.txt / package.json`，找 gadget 依赖
  - SSTI：Read 模板引擎初始化代码，找是否启用了用户输入作为模板源
  - JNDI：Read JDK 版本（`java.version` 或 manifest）
- **通过条件**：运行时前提可在生产存在（或攻击者可触发）
- **失败处理**：前提不存在 → 标「待验证」并列明"需运行时确认 X"，**不丢弃**

## 2. 7 步通过率与最终结论的映射

| R1-R7 通过情况 | 最终标记 | 处置 |
|---------------|---------|------|
| 全部通过 | 已确认 | 进入 phase4，标 V1+ |
| R1-R6 通过 + R7 待运行时验证 | 待验证（HYPOTHESIS） | 进入 phase4，「待验证内容」字段列 R7 缺失项 |
| R5 发现绕过 + R1-R4/R6 通过 | 已确认 | 进入 phase4，**优先级提升** |
| 任一 R1-R6 不通过 | 排除 | 写负证据进入 `false_positive_notes.md` |
| R2/R3 不通过（sink 未调用 / 未生产加载） | 排除或待验证（视证据强度） | 完全无调用证据 → 排除，写负证据 + 记入 `coverage_matrix.md`"已排除"列；有间接调用迹象 → 待验证 |

## 3. 反向审查（应对模型"看到 sink 就报"的过激）

进入 phase4 前对每条候选反向问：

- 这个 sink 真的被调用了吗？（R2）
- 调用它的类真的被生产加载了吗？（R3）
- 路由/全局拦截器有没有把它兜住？（R4 + R5）
- source 真的可控吗？（R6）
- 运行时条件存在吗？（R7）

**如果答案是"很可能但我没确认" → 必须按 R 算法去 Read 验证**，不得用"应该是"推论。

## 4. 与 callchain 产物的关系（Phase 2 vs Phase 4 分级）

**Phase 2**（`callchain_batch{N}.md`）：使用三级分层（简单/中等/复杂）+ 核心三点确认（sink 可达 / source 可控 / 防护缺失），不要求 R1-R7 完整打勾。格式示例：

```
## cc-007: SQL 注入候选 / UserController.findUser
可达性：sink可达 ✓ | source可控 ✓ | 防护缺失 ✓
调用链：
  UserController.java:45  — @PathVariable String id（外部输入）
  → UserService.java:102  — findUser(id) 参数传递
  → UserDao.java:33       — Statement.executeQuery("...WHERE id=" + id)（sink）
防护分析：无 schema 校验，SecurityConfig permitAll
判定：候选成立
```

**Phase 4**（`callchain_tracker.md`，由 Phase 3 合并后供 Phase 4 使用）：R1-R7 完整验证。每个 `cc-NNN` 块顶部必须包含 R1-R7 的 7 个打勾，例如：

```
## cc-007: SQL 注入候选 / UserController.findUser
R1. sink 存在        ✓  UserDao.java:33 Statement.executeQuery
R2. sink 被调用      ✓  UserService.java:102 调用 findUser
R3. 生产路径加载     ✓  UserController 有 @RestController 注解
R4. 路由对外         ✓  /api/users/{id} 在 application.yml 中暴露
R5. 全局拦截         ✗  SecurityConfig 第 45 行 .antMatchers("/api/users/*").permitAll()
R6. source 可控      ✓  @PathVariable String id，无 schema 校验
R7. 运行时前提       ✓  无特殊依赖
结论：已确认（R5 是绕过点）

[调用链跳转标记按 taint_propagation.md §1 节点类型]
[S] UserController.java:45 ...
```

## 5. applicability（模型代际标签）

| 步骤 | 模型预训练覆盖度 | 何时可裁剪 |
|------|----------------|----------|
| R1 sink 定义 | 高（基本不漏） | 模型 V5+ 后可简化 |
| R2 实际调用 | **中**（模型常忽略"sink 仅在 test 调用"） → 长期保留 | 长期保留 |
| R3 生产加载 | **低**（Profile/Bean 注册敏感） → 私有项目知识 | 长期保留 |
| R4 路由可达 | 中（取决于框架熟悉度） | 长期保留 |
| R5 全局拦截绕过 | **低**（前缀/大小写/编码绕过常被遗漏） → **必须保留** | 长期保留 |
| R6 source 可控 | 高 | 模型 V5+ 后可简化 |
| R7 运行时前提 | **中**（gadget 链、JDK 版本敏感） → 保留 | 长期保留 |

## 6. 与现有 skill 的接线

- `audit-sink/SKILL.md`（Phase 2）：在 "防护点判断" 步骤中使用三级分层（简单/中等/复杂）+ 核心三点确认（sink 可达 / source 可控 / 防护缺失）。R1-R7 完整验证在 Phase 4 执行。
- `audit-validate/SKILL.md`（Phase 4）：在 "反向审查" 处执行 R1-R7 完整复核。
- `callchain_batch{N}.md`（Phase 2）：每个 `cc-NNN` 块顶部标注核心三点确认结果。
- `callchain_tracker.md`（Phase 3 合并后，供 Phase 4 使用）：每个 `cc-NNN` 块顶部加 R1-R7 完整标记。
