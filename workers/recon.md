# recon worker

## 职责

建立项目画像和攻击面，为后续 audit worker 生成可执行 intent。

## 输入

- 项目根路径。
- 授权范围。
- 审计模式。
- 生产配置。

## 输出

- `project.schema.json` 兼容对象。
- `attack-surface.schema.json` 兼容对象。
- coverage seed。
- recon events。

## 已实现能力

`recon_worker.py` 提供生产闭环所需的确定性项目画像与攻击面种子扫描：

```bash
python3 workers/recon_worker.py \
  --project-root . \
  --audit-dir audit-v2 \
  --project-id proj-default \
  --audit-mode redteam \
  --source-shape source-only
```

输出：

- `audit-v2/project.json`
- `audit-v2/attack_surface.json`

已实现文件枚举、语言识别、入口关键词、source 关键词、sink 关键词和 secret 关键词扫描。后续语义审计必须基于这些结构化产物继续补强，不能把 recon 结果直接当作漏洞结论。

对 `compiled-only` 或 `mixed` 项目，recon 还会识别 `.jar`、`.war`、`.ear`、`.class`、`.dex`、`.apk`、`.dll`、`.exe`、`.so`、`.dylib` 等编译产物，并在 `project.json.decompilation` 中记录反编译需求和推荐资产。

## 必须识别

- 源码 / 编译产物 / 混合形态。
- 语言、框架、构建系统。
- HTTP/RPC/MQ/CLI/Scheduler/File entry。
- Source。
- Sink。
- 认证与授权模型。
- Secret 线索。
- 编译产物与反编译需求。
- 依赖和已知系统情报。

## 禁止

- 不做漏洞定性。
- 不编造路径。
- 不跳过反编译决策。
- 不把 Markdown 当权威 project profile。
