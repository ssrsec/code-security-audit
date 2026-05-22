# Skill ROI 测评框架（bench）

A/B 对照测评 skill 改动前后的召回 / 准确 / Token / 时长 / 报告字段完整度。

## 目录约定

```
scripts/bench/
├── README.md                ← 本文件
├── cases/                   ← 金本 case（已知漏洞答案集）
│   ├── case-001-fastjson/
│   │   ├── target/          ← 靶项目源码（git submodule 或符号链接）
│   │   ├── expected.yaml    ← 期望发现的漏洞清单 + OWASP 映射 + CVSS 区间
│   │   └── notes.md         ← case 设计意图与覆盖维度
│   └── ...
├── runs/                    ← 单次运行产物
│   └── 20260522-093000-A-with-skill/
│       ├── audit/           ← 该次审计的完整产物
│       ├── metrics.json     ← token / tool-calls / 时长
│       └── report.md
├── report.md                ← 跨 run 的 ΔROI 汇总（每次改动后追加）
└── run.sh                   ← 一键运行（待实现）
```

## 测评维度（必出指标）

| 维度 | 测度方式 | 来源 |
|------|----------|------|
| 漏洞召回率 | `len(命中) / len(expected.yaml)` | 报告 × expected |
| 漏洞准确率 | `len(命中) / len(报告中所有 vul)` | 报告 × expected |
| 误报率 | `1 - 准确率` | 同上 |
| Token 消耗 | input + output + cache 命中率 | 模型 API 账单或代理日志 |
| 工具调用次数 | Read / Glob / Grep / Bash 总数 | claude/cursor 会话日志 |
| 报告字段完整度 | 占位符违规计数 + CVSS 缺失计数 + 章节缺失计数 | 自动 lint（待实现 `lint_report.py`） |
| 阶段隔离违规 | 是否出现"phase4 部分完成 + 阶段 5 已开始"等混杂 | 状态日志检查 |

## 运行模式

每个 case 至少跑两次：

| run 标识 | skill 状态 | 用途 |
|---------|-----------|------|
| `A-with-skill` | 加载完整 `code-security-audit` skill | 实验组 |
| `B-without-skill` | 不加载任何 skill | 对照组（裸模型） |
| `C-with-skill-old` | 加载改动前的 skill 版本 | 回归对照（可选） |

每次 skill 主体改动后，必须跑 `A` + `C` 对照，输出"本次改动带来的 Δ召回 / Δ准确率 / Δ token / Δ时长"到 `report.md`。

## 金本 case 设计原则

- **覆盖核心 OWASP Top 10 适用域**：A01 / A03 / A06 / A08 / A10 各至少 1 个 case。
- **覆盖反编译路径**：至少 1 个 case 使用 `.war`/`.jar` 而非源码。
- **覆盖组合漏洞**：至少 1 个 case 含 2-3 个单漏洞 + 1 个攻击链。
- **覆盖待验证漏洞**：至少 1 个 case 含"Fastjson 老版本但 gadget 链不完整"类需要标待验证的项。
- **expected.yaml 用最小字段**：`vul_id / type / file:line / owasp / cvss_range / severity / verification_state`。

## 起步建议（从 1 个 case 开始）

```yaml
# cases/case-001-fastjson/expected.yaml
case: fastjson-1.2.47-rce
target_lang: java
target_framework: spring-boot
expected_vulns:
  - vul_id: f-001
    type: insecure-deserialization
    file: src/main/java/com/example/JsonController.java
    line: 45
    owasp: A08
    cvss_range: [8.0, 9.8]
    severity: critical
    verification_state: [已确认, 待验证]   # 允许的状态集
    notes: Fastjson 1.2.47 默认 autoType + 未启 safeMode → JdbcRowSetImpl gadget
```

## 当前进度

- [x] 测评框架结构定义（本 README）
- [ ] `case-001-fastjson` 靶项目接入（待用户授权后用公开靶场如 vulnhub-spring）
- [ ] `lint_report.py`（占位符 / CVSS / 章节自动检查）
- [ ] `run.sh`（一键跑 A + B 并产出 report.md 增量行）
- [ ] 与 GitHub Actions / 本地 hook 联动
