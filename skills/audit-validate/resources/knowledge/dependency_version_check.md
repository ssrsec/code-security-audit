# 依赖版本获取（通用）

供 阶段 4 在**无法从构建文件直接得到依赖版本**时，按技术栈扫描依赖目录或锁文件，提取版本并写入审计结论。**适用于任意语言与框架。**

---

## 何时使用

- 项目无构建文件（如无 pom.xml、build.gradle、package.json、requirements.txt、composer.json、go.mod 等）。
- 构建文件存在但未列出某依赖（如直接放 jar 到 lib、或本地 path 引用）。
- 需要确认**实际随包发布的依赖版本**（与构建声明可能不一致）。

---

## 按技术栈的常见来源

| 技术栈 | 构建/锁文件 | 依赖目录 | 版本提取方式 |
|--------|--------------|----------|--------------|
| Java (Maven) | pom.xml, *-dependencies.txt | lib/, WEB-INF/lib/, target/ | 从 jar 文件名（如 fastjson-1.2.6.jar）或 dependency-tree |
| Java (Gradle) | build.gradle, gradle.lockfile | build/libs/, lib/ | 同上 |
| Node | package.json, package-lock.json, yarn.lock | node_modules/ | package.json 的 version；锁文件精确版本 |
| Python | requirements.txt, Pipfile, setup.py, pyproject.toml | site-packages/, venv/ | 包目录名或 metadata |
| PHP | composer.json, composer.lock | vendor/ | composer.lock 或 vendor/包名/composer.json |
| Go | go.mod, go.sum | 通常无“依赖目录” | go.mod / go.sum |
| .NET | *.csproj, packages.lock.json | packages/, bin/ | 包目录名或 lock 文件 |

---

## 通用步骤

1. **识别技术栈**：根据 阶段 1 侦察结果（存在 pom.xml / package.json / requirements.txt 等）。
2. **优先读构建/锁文件**：能直接得到版本则不必扫目录。
3. **扫依赖目录**：按上表找到 `lib`、`node_modules`、`vendor`、`site-packages`、`WEB-INF/lib` 等，根据**文件名或包内 metadata** 提取版本（如 `fastjson-1.2.6.jar` → 1.2.6）。
4. **报告约定**：若版本来自依赖目录，在漏洞条目中写明「依赖目录已检查到 xxx@版本」或「lib 目录已检查到 xxx-x.y.z.jar」，避免“版本未确认”却未说明已扫过目录。

---

## 注意

- 不维护各语言的解析代码库；AI 按本表与项目实际路径执行 Read/List 即可。
- 其他生态（Ruby、Rust、Swift 等）可仿照本表增加一行「构建文件 + 依赖目录 + 提取方式」。
