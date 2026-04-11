---
name: audit-sink
description: 阶段 2 Sink-driven 审计。从危险 API 往上追踪数据流，判断用户输入是否可达 Sink，发现注入/反序列化/SSRF/文件操作等漏洞。
---

# Sink-driven 审计（阶段 2）

## 角色

负责 阶段 2 的 Sink-driven 轨道：从危险代码往上追踪数据流，判断用户输入是否可达 Sink 且无有效过滤。**只记录有实际攻击路径的发现**，丢弃理论风险。

## 漏报红线（严禁遗漏数据流漏洞）

- 必须完整追踪数据流，不能因为方法调用链较深就中途放弃。
- 绝不能主观臆断某些入口“不会被恶意用户调用”。只要从公网端点（或内部可达端点）能通过入参将污染数据传入 Sink，且未经过滤，必须作为候选漏洞上报。
- 任何形式的文件操作（上传、读取、写入）、执行层（SQL、命令执行、反序列化等），只要发现就必须记录。

## 极致降噪原则（严禁报告非漏洞项）

- **只报告能导致获取权限、数据泄露、篡改、系统被控的漏洞。**
- **严禁**将“整文件注释的死代码”、“配置文件存在但没有外部可控入口”、“使用了系统环境变量/启动参数”（如 `CivilCodeFileConf`）、“日志输出格式（如输出 SQL 日志到 StdOut）”当作漏洞报告！这些属于维护性或配置缺陷，根本没有攻击者可控的触发路径。
- 如果用户输入不可控（例如：只是框架自带的功能、配置属性注入、重启函数没有绑定到 HTTP 等），则**直接无视并跳过，不要为其分配 findings 编号！**
- 不要报告代码规范问题、设计模式问题或“未来可能会被利用”的假设性场景。必须有**现实中的外部触发入口**。

## 上下文保护规则（必须遵守）

1. **精准读取**：超过 500 行的文件不要整文件 Read。先用 Grep 定位 Sink，再用 Read 的 offset/limit 只读前后 50-100 行。
2. **调用链追踪器**：跨 2 个以上文件的数据流追踪，必须将每一跳写入 `audit/phase2/callchain_tracker.md` 再跳转到下一个文件，防止上下文丢失。格式：
```
## com-001: [Sink 类型]
1. 入口: UserController.java:45 — 参数 userId 来自 @RequestParam
2. 中转: UserService.java:102 — 传入 findUser() 的 id 参数
3. Sink: UserDao.java:33 — 拼接进 SQL 字符串
状态: 已确认
```

## 审计步骤

### 1. 确定 Sink 清单
根据 `audit/phase1/sink_list.md` 和知识库，列出需关注的危险 API。

### 2. 逐文件审计
- 对分配的文件执行 Read，定位 Sink 出现位置。
- 不得仅凭 Grep 结果报洞，必须 Read 确认上下文。
- T1 文件完整 Read；T2/T3 先筛后读。

### 3. 追踪数据流
从 Sink 参数向上追踪来源，直至入口或确认不可达：
- 优先使用 LSP（goToDefinition、findReferences）
- LSP 不可用时用 Grep + Read 逐跳验证

### 4. 重点关注的高级攻击向量

- **二次注入**：输入安全入库，但后续查出后拼接进另一个 SQL/命令
- **SSRF 绕过**：URL 可控 + 未校验内网 IP/重定向/DNS 重绑定
- **反序列化链**：Fastjson/Jackson/pickle/yaml + 不安全配置 + 可利用 Gadget
- **模板注入（SSTI）**：用户输入控制模板内容（非模板变量）
- **路径遍历**：filepath.Join/Path.resolve + 用户输入未 Clean
- **表达式注入**：导出/报表接口中 spEL/OGNL/formula 等表达式字段用户可控
- **原型污染**（Node.js）：深合并/Object.assign 未阻止 __proto__

### 5. 记录发现
- 写入 `audit/phase2/findings_batch{N}.md`
- 更新 `audit/phase2/reviewed_paths_batch{N}.txt`
- 数据流不清晰的标为**待验证**

### 6. 进度追踪（每轮必须）
每审完一批文件后：
1. 追加已审路径到 `audit/phase2/reviewed_paths_batch{N}.txt`
2. 统计已审/总数
3. 更新 `audit/phase2/progress.md`
4. 输出进度：`审计进度：已审 X / 总计 Y 文件 — Z% 覆盖率`

## 调用链记录约定

- 每一跳标注**文件:行号**
- 无法确认的跳标"待确认"，整条链标为待验证
- 代码片段仅来自 Read，不得编造

## 输出

候选漏洞和审阅清单写入 `audit/phase2/`，最终由 audit-validate 做成立条件判断。
