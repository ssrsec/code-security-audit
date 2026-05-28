#!/usr/bin/env python3
"""Render internal full-evidence report from structured data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            rows.append(json.loads(text))
    return rows


def index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("id")): row for row in rows if row.get("id")}


def code_block(info: str, content: str) -> str:
    return f"```{info}\n{content.rstrip()}\n```"


def render_finding(
    finding: dict[str, Any],
    requests: dict[str, dict[str, Any]],
    evidence: dict[str, dict[str, Any]],
    capabilities: dict[str, dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append(f"### {finding.get('id')} — {finding.get('title')}")
    lines.append("")
    lines.append("| 字段 | 内容 |")
    lines.append("|---|---|")
    lines.append(f"| 漏洞编号 | `{finding.get('id')}` |")
    lines.append(f"| 状态 | {finding.get('status', '')} |")
    lines.append(f"| 等级 | {finding.get('severity', '')} |")
    lines.append(f"| 验证等级 | {finding.get('validationLevel', '')} |")
    lines.append(f"| 认证级别 | {finding.get('authLevel', '')} |")
    cvss = finding.get("cvss") or {}
    lines.append(f"| CVSS | `{cvss.get('vector', '')}` / {cvss.get('score', '')} |")
    lines.append("")

    preconditions = finding.get("preconditions") or []
    if preconditions:
        lines.append("#### 前置条件")
        lines.extend(f"- {item}" for item in preconditions)
        lines.append("")

    required_caps = finding.get("requiresCapabilities") or []
    if required_caps:
        lines.append("#### 依赖能力")
        for cap_id in required_caps:
            cap = capabilities.get(cap_id, {})
            lines.append(f"- `{cap_id}` — {cap.get('name', '')}")
        lines.append("")

    poc_refs = finding.get("pocRefs") or []
    if poc_refs:
        lines.append("#### 复现请求")
        for req_id in poc_refs:
            req = requests.get(req_id)
            if not req:
                lines.append(f"- 缺失请求 `{req_id}`")
                continue
            lines.append(f"##### `{req_id}` ({req.get('purpose', '')})")
            lines.append(code_block("http", req.get("raw", "")))
            lines.append("")

    evidence_refs = finding.get("evidenceRefs") or []
    if evidence_refs:
        lines.append("#### 证据")
        for ev_id in evidence_refs:
            ev = evidence.get(ev_id)
            if not ev:
                lines.append(f"- 缺失证据 `{ev_id}`")
                continue
            lines.append(f"##### `{ev_id}`")
            if ev.get("responseSnippet"):
                lines.append(code_block("text", ev["responseSnippet"]))
            for assertion in ev.get("assertions") or []:
                lines.append(f"- 断言 `{assertion.get('type')}`：expected=`{assertion.get('expected')}` actual=`{assertion.get('actual')}` passed=`{assertion.get('passed')}`")
            lines.append("")

    fix = finding.get("fix") or {}
    if fix:
        lines.append("#### 修复建议")
        if fix.get("emergency"):
            lines.append(f"- 紧急方案：{fix['emergency']}")
        if fix.get("longTerm"):
            lines.append(f"- 长期方案：{fix['longTerm']}")
        if fix.get("businessImpact"):
            lines.append(f"- 业务影响：{fix['businessImpact']}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render(audit_dir: Path) -> str:
    model = load_json(audit_dir / "report_model.json", {})
    findings = index(load_jsonl(audit_dir / "findings.jsonl"))
    requests = index(load_jsonl(audit_dir / "requests.jsonl"))
    evidence = index(load_jsonl(audit_dir / "evidence.jsonl"))
    capabilities = index(load_jsonl(audit_dir / "capabilities.jsonl"))
    attack_chains = index(load_jsonl(audit_dir / "attack_chains.jsonl"))

    project = model.get("project") or {}
    finding_ids = model.get("findings") or list(findings)
    summary = model.get("summary") or {}
    coverage = model.get("coverage") or {}

    lines: list[str] = []
    lines.append(f"# {project.get('name', '代码安全审计报告')}")
    lines.append("")
    lines.append("> 内部权威报告：不脱敏，保留完整复现和证据引用。")
    lines.append("")
    lines.append("## 一、项目代码审计总结")
    lines.append("")
    lines.append(f"- 项目路径：`{project.get('projectRoot', '')}`")
    lines.append(f"- 审计模式：`{project.get('auditMode', '')}`")
    if coverage:
        lines.append(f"- 攻击面：entries={coverage.get('entries', 0)} sinks={coverage.get('sinks', 0)} secrets={coverage.get('secrets', 0)}")
    if summary:
        lines.append(f"- 可报告漏洞：{summary.get('reportableFindings', len(finding_ids))}")
        lines.append(f"- 组合链：{summary.get('attackChains', len(model.get('chains') or []))}")
    lines.append("")
    lines.append("## 二、漏洞汇总表")
    lines.append("")
    lines.append("| 漏洞编号 | 名称 | 等级 | 状态 |")
    lines.append("|---|---|---|---|")
    for fid in finding_ids:
        finding = findings.get(fid)
        if not finding:
            lines.append(f"| `{fid}` | 缺失 finding | - | missing |")
            continue
        lines.append(f"| `{fid}` | {finding.get('title', '')} | {finding.get('severity', '')} | {finding.get('status', '')} |")
    lines.append("")
    lines.append("## 三、漏洞详情")
    lines.append("")
    for fid in finding_ids:
        finding = findings.get(fid)
        if finding:
            lines.append(render_finding(finding, requests, evidence, capabilities))
            lines.append("")
    lines.append("## 四、组合漏洞摘要")
    lines.append("")
    for chain_id in model.get("chains") or []:
        chain = attack_chains.get(chain_id)
        if not chain:
            lines.append(f"- `{chain_id}`（缺失结构化链）")
            continue
        value = ", ".join(chain.get("valueIncrease") or [])
        lines.append(f"- `{chain_id}` status={chain.get('status')} type={chain.get('chainType')} value={value}")
        for edge in chain.get("edges") or []:
            lines.append(f"  - `{edge.get('from')}` -> `{edge.get('to')}`：{edge.get('transfer')}")
    if not model.get("chains"):
        lines.append("> 暂无结构化组合链。")
    lines.append("")
    lines.append("## 五、总体安全建议")
    lines.append("")
    for rec in model.get("recommendations") or []:
        if isinstance(rec, dict):
            lines.append(f"- {rec.get('title', rec.get('text', ''))}")
        else:
            lines.append(f"- {rec}")
    if not model.get("recommendations"):
        lines.append("- 根据结构化 findings 和 attack graph 制定修复优先级。")
    limitations = model.get("limitations") or []
    if limitations:
        lines.append("")
        lines.append("### 限制与待验证项")
        for item in limitations:
            lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Render internal report")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--output")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    output = Path(args.output) if args.output else audit_dir / "reports" / "security_audit_report.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(audit_dir), encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
