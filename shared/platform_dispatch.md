# 跨平台 Agent 调度策略

本文件定义 audit-orchestrator 在不同宿主平台上的子 Agent 调度方式、并行执行模式和失败恢复机制。

---

## 1. 平台检测

orchestrator 启动时必须检测当前宿主平台，以选择正确的调度方式：

| 检测方式 | Claude Code (CC) | Cursor |
|----------|------------------|--------|
| 可用工具 | `Agent` 工具 | `Task` 工具 |
| Agent 定义 | `agents/` 目录下的 `.md` 文件 | 无自定义 Agent，使用 `subagent_type` |
| 典型线索 | 能直接调用 `Agent(name="audit-recon-agent", ...)` | 能调用 `Task(subagent_type="generalPurpose", ...)` |

**检测规则**：
1. 如果环境中有 `Agent` 工具 → 使用 CC 模式
2. 如果环境中有 `Task` 工具（含 `subagent_type` 参数）→ 使用 Cursor 模式
3. 两者都没有 → 降级为单 Agent 顺序执行模式（orchestrator 自己完成所有阶段）

---

## 2. 调度方式对照

### Claude Code 模式

```
Agent(
  name="audit-recon-agent",
  prompt="执行 Phase 1 侦察。项目路径：{project_path}。读取 audit/phase0/metrics.md 后按 skills/audit-recon/SKILL.md 执行。"
)
```

- 子 Agent 从 `agents/audit-recon-agent.md` 读取完整行为定义
- 支持 `model`、`tools` 等元数据字段
- 并行：在同一消息中发多个 `Agent()` 调用

### Cursor 模式

```
Task(
  subagent_type="generalPurpose",
  description="Phase 1 项目侦察",
  prompt="你是 audit-recon-agent，负责执行代码安全审计的 Phase 1 侦察阶段。\n\n[读取 skills/audit-recon/SKILL.md 获取完整指令]\n\n项目路径：{project_path}\n前置产出：audit/phase0/metrics.md\n\n按 SKILL.md 中的步骤执行，所有产出写入 audit/phase1/。",
  run_in_background=true
)
```

- 使用 `subagent_type="generalPurpose"`，通过 prompt 注入 Agent 行为
- prompt 必须包含足够上下文（子 Agent 不继承父会话状态）
- 并行：在同一消息中发多个 `Task()` 调用

### 降级模式（单 Agent）

当 Agent/Task 工具都不可用时，orchestrator 自己按顺序执行每个阶段：
1. 读取对应 skill 的 SKILL.md
2. 按其中的步骤直接执行
3. 完成后继续下一阶段

---

## 3. 并行调度模式

### Phase 2：双轨并行

| 平台 | 调度方式 |
|------|----------|
| CC | 同一消息中 `Agent("audit-sink-agent", ...)` + `Agent("audit-control-agent", ...)` |
| Cursor | 同一消息中两个 `Task(subagent_type="generalPurpose", ...)` |
| 降级 | 先执行 Sink-driven，再执行 Control-driven（串行） |

### Phase 5：漏洞组合 + 原语组合并行（Phase 4 validate 必须先完成）

| 平台 | 调度方式 |
|------|----------|
| CC | 同一消息中 `Agent("audit-composite-agent", ...)` + `Agent("audit-primchain-agent", ...)` |
| Cursor | 同一消息中两个 `Task(subagent_type="generalPurpose", ...)` |
| 降级 | 先执行 composite，再执行 primchain（串行） |

---

## 4. 失败恢复机制

### 4.1 子 Agent 超时

**检测**：子 Agent 返回时间超过预期（大项目 Phase 2 可能需要较长时间，但不应无限等待）。

**恢复策略**：
1. 检查 `audit/` 目录下是否有部分产出（批次文件、findings 等）
2. 若有部分产出 → 读取已完成部分，更新 `state.json`，重新调度处理剩余部分
3. 若无任何产出 → 记录失败原因，重试一次（使用更小的批次或更精简的 prompt）
4. 重试仍失败 → 降级为 orchestrator 自己执行该阶段

### 4.2 子 Agent 返回错误或空结果

**检测**：子 Agent 返回但产出文件不存在、为空或格式异常。

**恢复策略**：
1. 验证预期输出文件是否存在且非空
2. 缺失文件 → 记录缺失项，重新调度该子 Agent（重试一次）
3. 文件存在但格式异常 → orchestrator 尝试修复或重新生成
4. 重试仍失败 → 将失败信息写入 `audit/state.json`，告知用户需要人工介入

### 4.3 覆盖率补扫失败

**检测**：Phase 3 发现覆盖率 < 100%，但重新调度 Phase 2 后覆盖率没有增长。

**恢复策略**：
1. 检查遗漏文件列表
2. 若遗漏文件为不可读/二进制 → 标记为 `skipped-with-reason`，重新计算覆盖率
3. 若遗漏文件可读但 Agent 跳过 → 将遗漏文件作为显式参数传入下一批次
4. 连续 2 次无进展 → 写入 `state.json`，告知用户并输出当前精确覆盖率

### 4.4 上下文耗尽

**检测**：Agent 感知到上下文即将耗尽。

**恢复策略**：
1. 立即将当前进度落盘（见 SKILL.md 上下文耗尽章节）
2. 告知用户发送「继续审计」
3. 新会话从 `audit/state.json` 恢复

---

## 5. Cursor 模式下的 Prompt 构造模板

子 Agent 在 Cursor 中没有独立的 Agent 定义文件，需要在 prompt 中完整传递角色、规则和上下文。

### 模板结构

```markdown
你是 {agent_name}，负责 {phase_description}。

## 核心规则
- 只关注有实际危害的漏洞（极致降噪）
- 遵守反幻觉铁律：文件路径必须 Glob/Read 验证，代码片段只来自 Read 输出
- 所有输出使用简体中文

## 执行指令
读取插件内 {skill_path} 获取完整执行步骤。

## 输入
{list_of_input_files}

## 输出要求
{list_of_output_files}

## 项目路径
{project_path}
```

### 关键约束

- prompt 总长度不应超过 2000 tokens（保留上下文给实际工作）
- 核心逻辑应引导 Agent 读取 SKILL.md 而非在 prompt 中重复
- 必须明确列出输入和输出文件路径
