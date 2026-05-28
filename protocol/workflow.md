# Workflow Protocol

## 目标

工作流支持生产级代码安全审计，而不是单次直线式扫描。工作流必须覆盖新审计、继续审计、补验、补丁报告、靶场异常和多 worker 并发。

## 状态机

```text
initialized
  -> recon
  -> audit_planning
  -> auditing
  -> coverage_gate
  -> validation_planning
  -> validating
  -> validation_gate
  -> attack_graph
  -> report_model
  -> render
  -> completed

completed
  -> supplemental_validation
  -> patch_report
  -> completed
```

异常状态：

```text
blocked_live_target
blocked_user_input
blocked_tooling
blocked_decompile
blocked_environment
paused
```

异常状态必须可恢复，不得丢失已完成事件、证据、finding 或 capability。

## 权威数据

权威状态保存在 `audit-v2/state.sqlite`。`audit-v2/events.jsonl` 是审计导出和人工追溯，不是并发写入权威源。

## 产物写入原则

- worker 只写结构化 fragment 或通过状态接口写入 SQLite。
- Markdown 只由 report renderer 生成。
- worker 不直接写最终报告。
- evidence、request、capability 只追加，不覆盖。
- finding 合并由 merge/quality gate 统一处理。

## Automation Responsibility

AI 负责按需自动执行：

- 创建项目本地 `.venv`。
- 安装 `requirements.txt` 中缺失依赖到 `.venv`。
- 运行 recon/audit/validate/chain/report/reviewer pipeline。
- 运行 quality gate、render gate、production check。
- 清理运行生成的缓存产物或确保它们被 `.gitignore` 忽略。

不得把 bootstrap、pip install、虚拟环境创建、普通脚本执行转嫁给工程师作为前置步骤。

## 补验

Phase 6 后继续验证 pending/deferred/hypothesis 是合法流程。

补验必须：

- 保留原报告版本。
- 记录补验事件。
- 更新 `report_model`。
- 生成 patch report。

## Hint

用户、运维或外部日志提供的信息写为 Hint。Hint 不直接成为事实，必须经 worker 验证后转为 evidence、finding 或 capability。

## Engineer Interaction Boundary

除以下情况外，审计流程不得要求工程师持续交互：

- 初始范围、审计模式、靶场地址、账号或约束信息。
- 复杂登录、MFA、验证码、SSO、设备绑定等 AI 无法自动完成的认证场景，需要工程师提供可审计的 Cookie、Token、会话生成步骤或测试账号状态。
- 靶场或环境异常，例如服务未启动、版本不一致、网络不可达、测试数据缺失、部署不完整。
- 当前操作系统不支持的工具执行，例如 macOS 下需要 Windows 环境运行的 .NET payload 工具；此时必须输出可复制命令、输入文件、期望输出和结果导入位置。
- L3 不可逆或高破坏动作的逐次授权。
- 单次 AI 上下文耗尽，需要工程师触发“继续审计”。

其他场景应由状态机、validation queue、dispatcher、quality gate 或 report limitations 自动处理，不应向工程师反复询问流程选项。

## 禁止

- 因报告已生成而拒绝补验。
- 因靶场 404 直接判白盒漏洞不成立。
- 因缺 Cookie 跳过认证相关验证。
- 用自然语言“同上/上一步”引用上下文。
- L2 操作无 cleanup 记录。
