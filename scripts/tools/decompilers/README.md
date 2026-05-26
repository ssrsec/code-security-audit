# 内置反编译工具

本目录提供 Java / .NET 编译产物的反编译能力，随 `code-security-audit` 仓库分发。CFR 反编译器已内置；ilspycmd 在首次使用时按当前操作系统自动安装。

## 环境要求与自动处理

| 组件 | 仓库内置 | 运行时依赖 | 自动安装策略 |
|------|---------|-----------|-------------|
| Java 反编译（CFR 0.152） | `java/cfr-0.152.jar` | `java`（JRE 8+） | 调用反编译脚本时自动检测；缺失时按 OS 尝试 `brew` / `winget` / `apt` 等安装 JRE |
| .NET 反编译（ilspycmd 9.1） | 安装到 `dotnet/` | `dotnet` SDK 8+ | 缺失或平台不匹配时自动执行 `dotnet tool install`；无 dotnet 时尝试 `winget` / `brew` 安装 SDK |

关闭自动安装（仅检测、报错）：

```bash
export DECOMPILERS_AUTO_INSTALL=0
```

Windows PowerShell：

```powershell
$env:DECOMPILERS_AUTO_INSTALL = "0"
```

## 目录结构

```
decompilers/
├── README.md
├── setup.sh / setup.ps1       # 可选：手动触发全量环境检测与安装
├── lib/
│   ├── ensure-env.sh          # 环境检测与自动安装（Unix）
│   └── ensure-env.ps1         # 环境检测与自动安装（Windows）
├── bin/
│   ├── decompile-java.sh / .cmd
│   ├── decompile-dotnet.sh / .cmd / .ps1
├── java/
│   └── cfr-0.152.jar
└── dotnet/                    # ilspycmd 安装目录（首次运行后生成）
```

## 使用方法

将 `SKILL_ROOT` 设为本仓库根目录。

### Java（JAR / WAR / CLASS）

macOS / Linux：

```bash
bash "$SKILL_ROOT/scripts/tools/decompilers/bin/decompile-java.sh" \
  /path/to/app.jar audit/decompiled/
```

Windows：

```cmd
"%SKILL_ROOT%\scripts\tools\decompilers\bin\decompile-java.cmd" ^
  C:\path\to\app.jar audit\decompiled
```

### .NET（DLL）

macOS / Linux：

```bash
bash "$SKILL_ROOT/scripts/tools/decompilers/bin/decompile-dotnet.sh" \
  /path/to/MyApp.dll audit/decompiled/
```

Windows：

```cmd
"%SKILL_ROOT%\scripts\tools\decompilers\bin\decompile-dotnet.cmd" ^
  C:\path\to\MyApp.dll audit\decompiled
```

脚本会在执行前自动调用 `ensure-env`；一般无需单独运行 `setup`。

### 手动初始化（可选）

```bash
bash scripts/tools/decompilers/setup.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\tools\decompilers\setup.ps1
```

## Phase 0 审计约定

1. 根据操作系统选择 `bin/` 下对应入口（`.sh` 或 `.cmd`）。
2. 仅使用本目录内置流程完成反编译，输出写入 `audit/decompiled/`。
3. **禁止未经用户同意降级**：内置脚本失败时，不得自行改用 jadx、在线反编译或字节码分析；须按 `shared/decompilation.md` 向用户说明并征得同意后再进入 Level 2/3。
4. 禁止在审计过程中临时 `curl` 下载第三方反编译器（本目录 `ensure-env` 的受控安装除外）。

## 维护

更新 ilspycmd：

```bash
dotnet tool update ilspycmd --tool-path scripts/tools/decompilers/dotnet
```
