# javachains 本地安装

`cli-chains.jar` 体积约 173MB，**未纳入 Git 仓库**（超过 GitHub 单文件 100MB 限制）。

## 获取方式

将 `cli-chains.jar` 放到本目录：

```
scripts/tools/javachains/cli-chains.jar
```

来源示例（任选其一）：

- 从团队内部分发渠道获取
- 从原始发布包复制（若你本机已有 `/Users/ssr/Downloads/javachains/cli-chains.jar`）：

```bash
cp /path/to/cli-chains.jar scripts/tools/javachains/cli-chains.jar
```

## 验证

```bash
java -jar scripts/tools/javachains/cli-chains.jar -h
```

`chains-config/` 目录已随仓库提供，无需单独下载。
