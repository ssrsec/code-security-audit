# javachains（Java 反序列化利用链生成器）

`cli-chains.jar` 体积约 173MB，超过 GitHub 单文件 100MB 限制，**未纳入 Git 仓库**。

## 下载与安装

从官方仓库 **[vulhub/java-chains](https://github.com/vulhub/java-chains)** 的 [Releases](https://github.com/vulhub/java-chains/releases) 页面下载最新的 CLI 版本 JAR，放置到本目录：

```
scripts/tools/javachains/cli-chains.jar
```

## 验证

```bash
java -jar scripts/tools/javachains/cli-chains.jar -h
```

## 说明

- `chains-config/` 目录（含第三方 gadget 库）已随仓库提供，无需单独下载
- 详细用法见 `scripts/tools/exploit_tools.md` 中的 javachains 章节
- 官方文档：https://java-chains.vulhub.org/docs/guide
