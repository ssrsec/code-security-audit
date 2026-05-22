# 污点传播形式化（taint propagation）

> **何时必读**：audit-sink 在 Phase 2 追踪 source-to-sink 时；audit-validate 在 Phase 4 复核 "防护是否有效" 时。
> **何时不需要读**：审计目标是纯 Control-driven（鉴权缺失）类漏洞、或单条 sink 与 source 在同一函数内（无跨函数传播）。
>
> 本文档规定调用链每一跳的节点类型、污点状态判定规则与跨进程传播规则，输出可复算的 6 类节点 + 4 阶段判定算法。

## 1. 节点分类（每一跳必标）

调用链 `callchain_tracker.md` 中每一跳必须明确节点类型：

| 类型 | 标记 | 含义 | 对污点的影响 |
|------|------|------|--------------|
| `SOURCE` | `[S]` | 外部输入入口（HTTP 参数、文件内容、MQ 消息、DB 二次污染） | **引入污点**（initial taint） |
| `PROPAGATOR` | `[P]` | 数据透传（赋值、参数传递、字段提取） | **保留污点**（taint preserved） |
| `TRANSFORMER` | `[T]` | 数据改写但**未消除危险**（base64、urlencode、JSON.parse、substring） | **变形污点**（taint transformed，可能改变可利用形式） |
| `SANITIZER` | `[X]` | **消除污点**（参数化查询、白名单匹配、Pattern.matches 正则全匹配、Path.normalize + startsWith 检查） | **清除污点**（taint cleared）|
| `BRANCH` | `[B]` | 控制流分支（if / switch / try-catch / 三元）| **分裂污点**（某分支带污点、某分支不带；必须对**每个分支独立标记**） |
| `SINK` | `[K]` | 危险 API 调用点 | **触发**（如果有污点 → 候选漏洞；否则排除） |

格式示例：

```
## cc-007: SQL 注入候选
[S] UserController.java:45      — @RequestParam String userId            taint=initial
[P] UserService.java:102        — findUser(id) 参数传递                     taint=preserved
[B] UserDao.java:31  if (id.matches("^[0-9]+$"))                         taint=conditional
  ├─[X]TRUE  分支 → return parameterizedQuery(id)                        taint=cleared
  └─[P]FALSE 分支 → fallback to legacy("SELECT * WHERE id=" + id)        taint=preserved
[K] UserDao.java:33             — Statement.executeQuery(sql)            ✓ sink_reached
判定：FALSE 分支可达 → 候选成立；TRUE 分支已清污 → 不构成
```

## 2. SANITIZER 真伪判别（防误判 sanitizer）

不是所有"看似清洗"的函数都是真 SANITIZER。**误判 SANITIZER 是漏报的头号成因**。判别四问：

| # | 问题 | 真 sanitizer 答案 | 反例（伪 sanitizer） |
|---|------|------------------|---------------------|
| 1 | 是否覆盖所有危险字符？ | 全字符白名单或框架级转义（如 `?` 占位符） | 仅过滤 `<script>` 但未过滤 `<iframe>` |
| 2 | 是否在**正确时机**调用？ | sink 调用前 | 调用后才校验（TOCTOU） |
| 3 | 是否**无绕过路径**？ | 单一入口必经 | 多入口仅部分调用、Filter 顺序后于 Handler |
| 4 | 是否**与 sink 上下文匹配**？ | HTML 转义 → HTML 输出 / SQL 转义 → SQL 拼接 | HTML 转义后用于 SQL（错位） |

四问任一为否 → 仍记为 PROPAGATOR，污点保留。

## 3. TRANSFORMER 不消污规则（防误判已清污）

以下变换**不消除污点**（攻击者可逆向构造）：

| 变换 | 不消污原因 |
|------|----------|
| `Base64 decode / encode` | 可逆 |
| `URL decode / encode` | 可逆，sink 通常自动解码 |
| `JSON.parse / serialize` | 攻击者可控制 JSON 结构 |
| `String.substring / split` | 部分污染仍可控 |
| `toLowerCase / toUpperCase` | 大小写不消污（如 `<SCRIPT>`） |
| `trim / strip` | 边缘空白不消污 |
| `Integer.parseInt` 之后 toString | 强类型转换，仅数字类污点失效（**对 SQL 注入有效**，对反序列化/SSRF 无效） |
| 长度判断（`length < 100`）| 缩小但不消污 |

只有第 7 行的强类型转换 `Integer.parseInt(x).toString()` 对**纯数字类 sink**（SQL `WHERE id=`）算清污；对其他 sink 仍是 TRANSFORMER。

## 4. BRANCH 分支判定（控制流敏感）

遇到 `if / switch / try-catch / 三元 / 短路 &&` 时：

1. **对每个分支独立标记**污点状态。
2. 只要存在**任意一个分支**保留污点到达 sink → 候选成立。
3. 攻击者控制的条件（如 `if (param == "admin")`）—— 攻击者可"选择"走哪个分支。
4. 业务自动条件（如 `if (DB_USER.equals(currentUser))`）—— 仅当攻击者能影响左侧时才算可控。

## 5. 上下文敏感（context sensitive）

同一函数被多处调用时，**必须对每个 caller 独立追踪**：

```
foo(x) → bar(x)                       (caller A: x 是用户输入 → 污点)
foo(x) → bar(x)                       (caller B: x 是常量 → 无污点)
bar(x) → Runtime.exec(x)              (sink 在 bar，从 caller A 链可达，caller B 不可达)
```

**不得**因 "bar 有多个 caller 中部分无污点" 就排除整个 bar 的 sink；也不得因 "bar 有部分 caller 有污点" 就标所有 caller 都有问题。**逐 caller 独立判定**。

## 6. 跨进程 / 跨存储污点延续

| 跨界 | 是否保留污点 |
|------|--------------|
| HTTP → DB → 另一接口读取 → 拼接 | **保留**（二次注入） |
| HTTP → Redis 缓存 → 反序列化 | **保留**（缓存污染） |
| HTTP → 日志文件 → 日志查询/分析回填 | **保留**（日志注入） |
| HTTP → MQ 消息 → consumer 反序列化 | **保留**（MQ 污染） |
| HTTP → 配置文件 / 环境变量（攻击者一般不可写） | **不保留** |

跨界保留时，**必须追踪写入入口**（哪些接口能写 Redis 这个 key、哪些 producer 能向 MQ topic 推消息），并把写入入口纳入 source 集合。

## 7. 4 阶段判定算法（与 audit-sink 候选 finding 输出对齐）

| 阶段 | 问题 | 通过条件 | 失败处理 |
|------|------|---------|----------|
| Q1 | sink 是否存在？ | Grep + Read 命中 | 不存在 → 丢弃 |
| Q2 | 是否有可控 SOURCE 可达？ | 通过 PROPAGATOR/TRANSFORMER 链回溯到 SOURCE 节点 | 不可达 → 排除（写负证据） |
| Q3 | 路径上是否**有效**清污？ | 按 §2 四问判定 SANITIZER 真伪 | 真清污 → 排除；伪清污 → 继续 |
| Q4 | 是否存在攻击者可达的分支？ | 按 §4 BRANCH 规则 | 仅自动条件且攻击者不可控 → 排除；否则候选成立 |

任一阶段排除时必须写入对应的负证据（按 audit-sink §5.1），不得静默丢弃。

## 8. applicability（模型代际标签）

| 节点 | 模型预训练覆盖度 | 何时本文档可裁剪 |
|------|----------------|---------------|
| §1 节点分类 | 高（多数模型懂 source/sink/sanitizer 概念） | 模型支持 native taint analysis 后可移除 |
| §2 SANITIZER 真伪 | **中**（模型容易把"过滤了部分字符"当真清污）→ **私有纪律必须保留** | 长期保留 |
| §3 TRANSFORMER 不消污 | **中**（模型容易把 base64/urlencode 当清污）→ **私有纪律必须保留** | 长期保留 |
| §4 BRANCH | 中 → 保留 | 长期保留 |
| §5 上下文敏感 | 中 → 保留 | 长期保留 |
| §6 跨界污点 | **低**（二次注入 / 缓存污染常被遗漏）→ **必须保留** | 长期保留 |
| §7 4 阶段算法 | 低 → 保留 | 长期保留 |

## 9. 与现有产物的关系

- `audit-sink/SKILL.md`：在 "调用链追踪器" 处引用本文档，按 §1 标记节点类型。
- `audit-validate/SKILL.md`：在 "反向审查" 处引用 §2 / §3 复核防护点是否伪 sanitizer。
- `callchain_tracker.md`（产物）：每个 `cc-NNN` 块必须按 §1 格式标记节点类型与污点状态。
