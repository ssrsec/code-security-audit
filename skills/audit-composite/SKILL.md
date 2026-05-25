---
name: audit-composite
description: 阶段 5 漏洞组合攻击链分析（漏洞+漏洞）。基于 audit-validate 输出的已确认/待验证单漏洞，推导多漏洞组合攻击链，输出 phase5/composite_findings.md。不负责单漏洞 V0-V4 验证（→ audit-validate）、不负责原语组合（→ audit-primchain-agent，由 orchestrator 在 Phase 5 并行调度两者）。当 orchestrator 完成 Phase 4 进入 Phase 5 漏洞组合轨道时触发。
---

# 阶段 5 漏洞组合分析

## Banned Patterns（零容忍）

- 禁止：基于"理论上可能"但没有阶段 4 实证证据的漏洞做组合推理。
- 禁止：把单漏洞改名后伪装成组合漏洞写入 `composite_findings.md`。
- 禁止：组合链不展示"能力转移证据"（A 的输出如何成为 B 的输入）。
- 禁止：组合后等级低于参与漏洞最高等级（组合的意义在于放大危害；若不放大则无价值）。
- 禁止：用 `prim-NNN` 编号参与组合（那是原语，归 `audit-primchain-agent` 负责，本 skill 只组合 `vul-NNN`）。

## 角色

阶段 5 漏洞组合轨道。读取 `audit/phase4/validated_findings.md`，对其中**所有已确认与待验证漏洞**做笛卡尔遍历，挑出能形成攻击链的组合，输出 `audit/phase5/composite_findings.md`。

与并行轨道 `audit-primchain-agent` 互不交叉：

| 轨道 | 输入 | 输出 | 责任人 |
|------|------|------|--------|
| 漏洞组合（本 skill） | `vul-NNN` × `vul-NNN` | `phase5/composite_findings.md` | audit-composite |
| 原语组合（并行） | `prim-NNN` × `prim-NNN`（含跨原语） | `phase5/primitive_chains.md` | audit-primchain-agent |

## 输入

- `audit/phase4/validated_findings.md`
- `audit/phase4/validation_results.json`
- `audit/phase1/auth_model.md`、`audit/phase1/endpoint_list.md`（理解攻击路径上下文）
- `shared/composite_vulnerability_analysis.md`（按需读取：组合规则模板）

## 组合判定流程

### 1. 能力转移检查（必要条件）

对任意 `vul-A` 与 `vul-B` 配对，仅当能列出明确的"能力转移路径"才记入组合：

| 转移类型 | 形态 |
|---------|------|
| 凭证→权限 | A 泄露 token/账密 → B 用此凭证调用高权接口 |
| 信息→定位 | A 泄露内部 ID/路径 → B 用此 ID 触发 IDOR/任意读 |
| 网络→可达 | A 提供 SSRF/隧道 → B 利用此通道打内网原本不可达的 sink |
| 文件→执行 | A 可写文件到特定路径 → B 触发该路径的反序列化/include/cron |
| 状态→绕过 | A 制造非法状态 → B 在该状态下绕过业务校验 |
| 数据→污染 | A 写入 Redis/MQ/DB 的数据 → B 反序列化或回显时触发 |

不满足任一转移类型 = 不是组合，不写入。

### 2. 组合等级判定

组合后等级必须 **严格高于参与漏洞最高单项等级**（否则无价值，丢弃）：

- 高危 + 中危 → 高危 / 严重（看危害放大幅度）
- 中危 + 中危 → 高危（如果链路打通获取实际权限或敏感数据）
- 严重 + 任何 → 严重

降级或持平 = 不写入。

### 3. 组合证据要求

每条组合必须给出：

- **参与漏洞**：`vul-A` + `vul-B`（最少 2 条；可 3+ 条但需说明每跳必要性）
- **攻击场景描述**：一句话讲清楚组合后能拿到什么
- **能力转移证据**：A 的实际输出 → B 的实际输入要素的对应关系（引用 phase4 已记录的响应/payload，不重新构造）
- **预演攻击链**：编号化步骤，每步对应一个具体接口/payload/期望响应
- **判定等级**与依据
- **修复优先级**：哪一个单漏洞修复后能阻断本链（用于推动业务先修哪个）

## 输出格式

写入 `audit/phase5/composite_findings.md`：

```markdown
## 组合漏洞汇总表

| 组合编号 | 涉及漏洞 | 攻击场景 | 组合后等级 | 阻断点 |
|---------|---------|---------|-----------|--------|
| comp-001 | vul-003 + vul-007 | SSRF 拿云元数据 token → 利用 token 访问内网 OSS 任意读 | 严重 | 优先修 vul-003 |

## 【组合详情】comp-001

- 参与漏洞：vul-003（SSRF）+ vul-007（OSS 鉴权仅校验 IAM token）
- 能力转移：vul-003 通过 169.254.169.254 拿到 STS token → vul-007 接受 IAM token 即可访问
- 攻击链：
  1. `GET /api/avatar?url=http://169.254.169.254/...` 拿 access_key + token
  2. `aws s3 cp s3://bucket/key -` 读取生产数据
- 等级：严重（CVSS 9.1，外部未授权 → 数据全量泄露）
- 修复优先级：先修 vul-003（SSRF 协议白名单）即可阻断链；vul-007 单独风险次之
```

无组合时写：`> 经分析，未发现可组合利用的漏洞链。`

## 进度与结束纪律

- 必须遍历 `validated_findings.md` 全部条目，不得抽样。
- 完成后追加一行 `> 已遍历 N 条单漏洞，命中 M 条组合链。` 到 `composite_findings.md` 末尾。
- 不得修改 `validated_findings.md` 中的单漏洞内容（只读输入）。
- 不得输出与原语相关的 `chain-NNN`（这是 `audit-primchain-agent` 的命名空间）。

## 输出

- `audit/phase5/composite_findings.md`（唯一交付物）
