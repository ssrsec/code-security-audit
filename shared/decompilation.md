# 编译产物反编译预处理

当审计目标不是源代码而是编译产物（如 JAR/WAR/CLASS、.NET DLL 等）时，必须在 阶段 0 中执行反编译预处理，将编译产物转换为可审计的源代码形态。

---

## 1. 输入类型识别

在 阶段 0 执行代码库度量时，必须判断审计目标的类型：

| 输入类型 | 典型文件 | 识别方式 |
|---------|---------|---------|
| **纯源代码** | `.java`、`.py`、`.go`、`.cs`、`.js`、`.php` 等 | 存在标准项目结构（src/、pom.xml、package.json 等） |
| **Java 编译产物** | `.jar`、`.war`、`.ear`、`.class` | 文件扩展名识别；可用 `file` 命令确认 ZIP/Java archive |
| **ASP.NET 编译产物** | `.dll`（.NET 程序集） | 文件扩展名为 `.dll`；可用 `file` 命令确认 PE32/PE32+ .NET assembly |
| **混合** | 同时存在源码和编译产物 | 询问用户确定审计形态 |

**判定规则**：
- 若目标路径下**无任何源代码文件**，仅有编译产物 → 自动进入反编译流程
- 若**同时存在**源码和编译产物 → 询问用户选择 `source_only` / `compiled_only` / `both`
- 若为纯源代码 → 跳过反编译，正常进入 阶段 1

---

## 2. 反编译工具使用

### 2.1 Java 编译产物（JAR/WAR/CLASS）

**优先使用仓库内置 CFR**（随 skills 分发，跨平台）：

**macOS / Linux：**
```bash
SKILL_ROOT="<本仓库根目录>"
bash "$SKILL_ROOT/scripts/tools/decompilers/bin/decompile-java.sh" <target.jar|target.class> audit/decompiled/
```

**Windows：**
```cmd
"%SKILL_ROOT%\scripts\tools\decompilers\bin\decompile-java.cmd" <target.jar> audit\decompiled
```

详见 `scripts/tools/decompilers/README.md`。内置 JAR：`scripts/tools/decompilers/java/cfr-0.152.jar`。**仅需本机已安装 `java`。**

**⚠️ 绝对禁止的行为**：
- 擅自通过 Bash 下载或安装反编译工具（如 `curl -O cfr.jar`、`pip install`、`brew install` 等），这属于越权操作
- 跳过反编译直接审计 .class/.dll 的二进制

**解压预处理（必须自行完成）**：
1. **WAR 包**：使用 `unzip` 或 `jar -xf` 自行解压，获取内部结构：
   - `WEB-INF/classes/` — 项目代码（业务代码 + 开发者自定义的框架覆盖类）
   - `WEB-INF/lib/` — 第三方依赖 JAR
   - `WEB-INF/web.xml`、`*.xml` — 配置文件（直接使用，无需反编译）
2. **FAT JAR（Spring Boot 等）**：使用 `unzip` 解压，获取：
   - `BOOT-INF/classes/` — 项目代码
   - `BOOT-INF/lib/` — 第三方依赖 JAR
3. **普通 JAR**：若为单个业务 JAR，直接使用 CLI 反编译
4. **lib/ 目录**：若用户给定的是一个包含多个 JAR 的目录，按下方筛选规则处理

**反编译范围判定规则（关键，必须严格遵守）**：

`WEB-INF/classes/`（或 `BOOT-INF/classes/`）和 `WEB-INF/lib/`（或 `BOOT-INF/lib/`）的处理逻辑**完全不同**：

#### ① `classes/` 目录 → 全量反编译

`classes/` 目录下的**所有 `.class` 文件都是项目代码**，必须全量反编译。这包括：
- 业务包（如 `com/myapp/`）— 项目核心业务代码
- `org/springframework/`、`org/activiti/` 等包下的类 — 这些**不是**第三方库原始代码，而是**开发者自定义的覆盖类**（如自定义 `FastJsonHttpMessageConverter`、覆盖的 `ProcessEngineConfigurationImpl` 等），从安全角度看可能比业务代码更关键
- `utils/`、`filter/`、`interceptor/`、`listener/` 等 — 项目公共组件

**严禁对 `classes/` 目录做包名筛选然后跳过部分类。** 如果一个 `.class` 文件出现在 `classes/` 目录而不是 `lib/` 下的 JAR 里，那它就是项目代码，必须反编译。

#### ② `lib/` 目录 → 按包名筛选，仅反编译业务 JAR

`lib/` 目录下是第三方依赖 JAR，绝大多数不需要反编译：
- 先从 `classes/` 目录结构推断出**业务包名前缀**（如 `com.edoc2Flow`、`com.mycompany` 等）
- 在 `lib/` 中查找文件名与业务包名相关的 JAR（即项目自身的子模块 JAR），只反编译这些
- 跳过明显的第三方 JAR（如 `spring-*.jar`、`commons-*.jar`、`log4j-*.jar`、`fastjson-*.jar`、`mysql-connector-*.jar` 等）
- **例外**：在 阶段 2/4 追踪数据流或分析 Gadget 链时，若需要查看特定第三方库内部实现，可**按需**对单个第三方 JAR 执行反编译，但不纳入 `in_scope_files.txt`
- 所有 `lib/` 下的 JAR 文件名和版本必须记录到 `audit/phase1/dependency_list.json` 用于依赖分析

**反编译执行**：
1. 使用 CLI 工具（cfr/procyon/fernflower）对 `classes/` 全量 + `lib/` 中筛选出的业务 JAR 进行反编译
2. 反编译输出目录记录到 `audit/phase0/metrics.md` 中的 `反编译输出路径` 字段
3. WAR/JAR 中的 XML 配置文件（如 MyBatis Mapper XML、Spring XML、web.xml）直接复制使用，无需反编译

### 2.2 ASP.NET 编译产物（DLL）

**优先使用仓库内置 ilspycmd**（调用脚本时自动检测环境并安装，见 `scripts/tools/decompilers/README.md`）：

**macOS / Linux：**
```bash
bash "$SKILL_ROOT/scripts/tools/decompilers/bin/decompile-dotnet.sh" <target.dll> audit/decompiled/
```

**Windows：**
```cmd
"%SKILL_ROOT%\scripts\tools\decompilers\bin\decompile-dotnet.cmd" <target.dll> audit\decompiled
```

脚本会自动安装 `dotnet` / ilspycmd（若本机包管理器可用）。无法自动安装时须向用户说明，**不得未经同意降级**。

**部署目录结构识别（必须先执行）**：

ASP.NET 有多种部署形态，部署目录中**不仅有 DLL**，还有需要直接审计的非编译文件。必须先识别变体：

| 变体 | 识别标志 | 典型结构 |
|------|---------|---------|
| **ASP.NET Core** | 存在 `*.runtimeconfig.json`、`*.deps.json`、`appsettings.json` | DLL + `wwwroot/` + `appsettings*.json` |
| **ASP.NET MVC 5 / WebAPI** | 存在 `bin/` + `Views/` + `Web.config`（大写 W） | `bin/` + `Views/*.cshtml` + `Web.config` + `Global.asax` |
| **ASP.NET WebForms** | 存在 `bin/` + `*.aspx` + `Web.config` | `bin/` + `*.aspx` + `*.ascx` + `App_Code/` + `Web.config` |

**非 DLL 文件的处理（直接审计，无需反编译）**：

以下文件类型包含服务端代码或安全相关配置，必须纳入 `in_scope_files.txt` 直接审计：

| 文件类型 | 说明 | 审计重点 |
|---------|------|---------|
| `*.cshtml` | Razor 视图，包含内联 C# 代码 | XSS、信息泄露、服务端逻辑 |
| `*.aspx` / `*.ascx` | WebForms 页面/控件 | 同上，注意 ViewState 反序列化 |
| `Web.config` / `web.config` | 主配置文件 | 连接字符串、machineKey、认证模式、自定义 Handler/Module |
| `appsettings*.json` | Core 配置 | 连接字符串、JWT 密钥、第三方服务凭据 |
| `Global.asax` | 应用生命周期 | 全局错误处理、路由注册 |
| `App_Code/*.cs` | WebForms 运行时编译的源码（若存在） | 与普通 C# 源码同等审计 |
| `*.config`（其他） | 如 `connectionStrings.config`、`log4net.config` | 敏感配置外置文件 |

**反编译范围判定规则**：

ASP.NET 部署中 DLL 通常集中在同一目录（`bin/` 或发布根目录），不像 Java 有 `classes/` 和 `lib/` 的天然分离。必须通过以下方法区分业务程序集和第三方依赖：

#### ① 利用 `.deps.json` 精确识别（首选方法）

`.deps.json` 是 ASP.NET Core 的依赖清单，结构为 JSON，其中：
- `targets` → `运行时标识` 下的每个条目即为一个依赖
- **项目自身的程序集**：`type` 为 `"project"` 或在 `libraries` 节中 `type: "project"`
- **NuGet 第三方依赖**：`type` 为 `"package"`

```
操作步骤：
1. 找到 *.deps.json 文件（通常与主 DLL 同名，如 MyApp.deps.json）
2. Read 该文件，提取 libraries 节中 type 为 "project" 的条目 → 这些是业务程序集
3. 其余 type 为 "package" 的条目 → 第三方依赖，记录到 dependency_list.json
```

#### ② 无 `.deps.json` 时的备选识别方法

对于 ASP.NET Framework（非 Core）项目，通常没有 `.deps.json`，按以下顺序尝试：

1. **从 `Web.config` 推断**：`<compilation>` 节的 `<assemblies>` 引用、`<httpModules>`/`<httpHandlers>` 注册的命名空间
2. **从目录名/项目名推断**：部署目录名通常与主程序集名一致
3. **按已知第三方前缀排除**：跳过以下前缀的 DLL：
   - `Microsoft.*`、`System.*`、`mscorlib`
   - `Newtonsoft.*`、`NLog.*`、`Serilog.*`、`log4net`
   - `AutoMapper.*`、`Dapper.*`、`EntityFramework.*`
   - `Antlr3.*`、`WebGrease`、`Owin.*`、`BouncyCastle.*`
   - `StackExchange.*`（如 Redis）
4. **剩余无法判定的 DLL → 全部反编译**：宁可多反编译几个，不可漏掉业务程序集

#### ③ 特别注意：不要遗漏多模块业务程序集

企业项目通常拆分为多个程序集（如 `MyApp.Web.dll`、`MyApp.Core.dll`、`MyApp.Data.dll`、`MyApp.Common.dll`），这些**全部是业务代码**，必须全部反编译。识别方式：
- 共享相同的名称前缀
- 在 `.deps.json` 中 `type` 均为 `"project"`
- 文件大小通常远小于第三方大型 DLL（如 `Microsoft.AspNetCore.*.dll`）

**反编译执行**：
1. 对筛选出的所有业务程序集使用 `ilspycmd` CLI 工具反编译为 `.cs` 文件
2. 反编译输出目录记录到 `audit/phase0/metrics.md`
3. 非 DLL 文件（`.cshtml`/`.aspx`/`.config`/`.json` 等）直接复制到审计范围，无需反编译
4. 所有 DLL 文件名和版本记录到 `audit/phase1/dependency_list.json`

### 2.3 三级降级策略（反编译失败时绝不放弃）

**反编译失败绝对不能跳过**。必须按以下顺序逐级尝试：

#### Level 1：内置 CLI（首选）

**必须先尝试仓库内置脚本**（`scripts/tools/decompilers/bin/`，见 `scripts/tools/decompilers/README.md`）：

| 语言 | 入口（按 OS 选择） | 前置条件 |
|------|-------------------|---------|
| Java | `decompile-java.sh`（macOS/Linux）或 `decompile-java.cmd`（Windows） | 本机 `java` |
| .NET | `decompile-dotnet.sh`（macOS/Linux）或 `decompile-dotnet.cmd`（Windows） | 本机 `dotnet` + 首次运行 `setup.sh` / `setup.ps1` |

执行逻辑：
1. 根据 OS 调用 `scripts/tools/decompilers/bin/` 下对应入口；脚本会自动检测环境并安装缺失依赖（见 `scripts/tools/decompilers/README.md`）
2. 输出写入 `audit/decompiled/`
3. 单文件失败 → 记录原因，继续处理其余文件
4. **Level 1 整体失败时不得自行降级**（见下）

**⚠️ 降级须用户明确同意**：Level 1 内置流程失败（含自动安装后仍失败）时，AI **必须暂停并向用户说明**失败原因与拟采用的备选方案，**仅在用户明确回复同意后方可**进入 Level 2 或 Level 3。禁止静默改用 jadx、PATH 中其他工具、在线反编译或字节码分析。

#### Level 2：用户同意后的协助方案

**前置条件：用户已明确同意降级。**

Level 1 不可用或执行失败时：
1. 告知用户当前环境缺少反编译工具，提供安装建议
2. 或请求用户在其他环境反编译后提供结果
3. 格式：
   ```
   当前环境无可用反编译工具，请协助处理：
   - /path/to/target.jar
   建议安装 jadx 后运行：jadx -d audit/decompiled/ /path/to/target.jar
   或在线反编译后将结果放入 audit/decompiled/ 目录
   然后发送「继续审计」
   ```

#### Level 3：字节码/IL 直接分析

**前置条件：用户已明确同意进入 Level 3（通常是在 Level 2 仍无法完成时）。**

Level 2 仍无法完成时：
1. 将失败文件列表写入 `audit/phase0/decompile_blocked.md`
2. 这些文件**仍计入覆盖率分母**，状态标为 `skipped-decompile-failed`
3. 在最终报告的「审计局限性」章节中明确列出
4. 尝试使用 `javap -c`（Java）或 `ildasm`（.NET）进行字节码/IL 级别的有限分析
5. **绝对禁止**：跳过不审、假装审了、把这些文件从覆盖率分母中去掉

### 2.4 按需补反编译（Phase 2 触发）

Phase 2 数据流追踪时，如果追入了未反编译的第三方包：
1. sink-agent 记录「需补反编译：xxx.jar 中的 com.lib.ClassName」
2. orchestrator 收到后按 Level 1 → Level 2 → Level 3 尝试反编译该单个类/包
3. 反编译成功 → 追加到 `audit/decompiled/`，sink-agent 继续追踪
4. 反编译失败 → 记录为阻塞项，该数据流追踪标注「到达第三方包边界，无法继续」

---

## 3. 反编译后的差异说明

反编译产生的代码与原始源码存在以下差异，审计过程中必须注意：

### 3.1 通用差异
- **变量名丢失**：局部变量可能被替换为 `var1`、`var2` 等，方法参数名可能丢失
- **注释丢失**：所有源码注释不可恢复
- **行号偏移**：反编译代码的行号与原始源码不一致，调用链中标注行号时应说明"反编译后行号"
- **代码结构变形**：lambda、switch 表达式、try-with-resources 等语法糖可能被展开为低级形式
- **内部类/匿名类**：可能被拆分为独立的 `ClassName$1.java` 文件

### 3.2 Java 特有差异
- **泛型擦除**：泛型信息部分丢失，`List<String>` 可能显示为 `List`
- **枚举/record**：可能被展开为普通类
- **Spring 注解**：`@RequestMapping`、`@Autowired` 等注解通常保留完好
- **MyBatis XML**：如 WAR 包中包含 XML Mapper 文件，直接使用原始 XML，无需反编译

### 3.3 ASP.NET 特有差异
- **属性语法**：自动属性可能被展开为完整的 getter/setter
- **async/await**：异步方法可能被展开为状态机类
- **LINQ**：查询表达式可能被展开为链式方法调用
- **特性（Attribute）**：`[Authorize]`、`[HttpGet]`、`[Route]` 等特性通常保留完好
- **Razor 视图**：`.cshtml` 文件无需反编译，但内联的 `@{ }` C# 代码块、`@Html.Raw()`、`@Model` 引用需要审计（关注 XSS 和信息泄露）
- **WebForms 代码后置**：`.aspx.cs` 编译后进入 DLL，反编译可恢复；但 `.aspx` 中的内联 `<% %>` 代码需直接审计
- **ViewState**：WebForms 项目需关注 `Web.config` 中 `machineKey` 配置和 ViewState 反序列化风险

### 3.4 对审计的影响
- **不影响漏洞发现**：SQL 拼接、命令执行、反序列化调用等 Sink 在反编译后仍然清晰可见
- **不影响控制流分析**：认证/授权注解、Filter 链、路由配置在反编译后通常保留
- **可能影响**：复杂的自定义过滤逻辑在反编译后可读性降低，需更仔细分析
- **报告标注**：最终报告中调用链的文件路径和行号应标注为"反编译后路径"，并在报告开头说明审计对象为反编译产物

---

## 4. 审计形态记录

在 `audit/phase0/metrics.md` 中必须记录：

```
审计形态：compiled_only（或 source_only / both）
原始输入：/path/to/target.jar（或目录路径）
反编译工具：cfr/procyon/fernflower CLI（或 ilspycmd CLI）
反编译输出路径：/path/to/decompiled/
注意事项：反编译代码的变量名、行号与原始源码可能存在差异
```

后续 阶段 1 的 `in_scope_files.txt` 应基于反编译输出路径枚举文件。

---

## 5. 反编译后的流程衔接（关键）

**反编译只是 阶段 0 的一个预处理子步骤，不是独立任务。** 反编译完成后，必须将反编译输出视为"源代码"，然后**严格按照 阶段 1 → 2 → 3 → 4 → 5 → 6 的完整流程**继续执行，与审计源代码项目的流程完全一致。

**⚠️ 绝对禁止的行为**：
- 反编译完成后直接跳到出报告（跳过 阶段 1-5）
- 反编译完成后自行决定"代码量不大，不需要分批"而省略 阶段 3 覆盖率校验
- 将反编译当作独立阶段，在反编译后向用户汇报"反编译完成"然后等待指令

**正确流程**：阶段 0（度量 + 反编译）→ 阶段 1（基于反编译输出做侦察）→ 阶段 2（基于反编译代码做审计）→ ... → 阶段 6（报告）

---

## 6. 清理规则

- `audit/decompiled` 目录是审计的源代码基础，**严禁在 阶段 6 清理时删除**
- 阶段 6 清理中间文件时严禁删除 `audit/decompiled`。最终交付报告必须是 `audit/security_audit_report.md`，并在报告正文内联关键证据。
- 如需要交付精简包，清理命令只针对 `audit/phase0`、`audit/phase1`、`audit/phase2`、`audit/phase3` 等阶段目录，不得包含 `audit/decompiled`。
