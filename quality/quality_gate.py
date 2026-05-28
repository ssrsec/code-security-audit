#!/usr/bin/env python3
"""quality gate CLI.

This CLI intentionally starts with deterministic checks that do not require
network access or model judgment. It never auto-fixes security evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - exercised only on missing dependency
    Draft202012Validator = None  # type: ignore[assignment]


BAD_PLACEHOLDER_PATTERNS = [
    r"REPLACE_[A-Z0-9_]+",
    r"YOUR_[A-Z0-9_]+",
    r"<上一步[^>]*>",
    r"同上",
    r"由客户端\s*jar\s*维护",
    r"\(同上\)",
    r"TODO",
]

HTTP_REQUEST_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/[^\s]*\s+HTTP/1\.[01]$", re.I)
BOUND_VARIABLE = re.compile(r"\{\{([A-Za-z0-9._-]+)\}\}")
ID_PATTERNS = {
    "finding": re.compile(r"^vul-[0-9]{3,}$"),
    "capability": re.compile(r"^cap-[A-Za-z0-9._-]+$"),
    "evidence": re.compile(r"^ev-[A-Za-z0-9._-]+$"),
    "request": re.compile(r"^req-[A-Za-z0-9._-]+$"),
    "chain": re.compile(r"^chain-[A-Za-z0-9._-]+$"),
}
SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
SCHEMA_FILES = {
    "project": "project.schema.json",
    "attackSurface": "attack-surface.schema.json",
    "findings": "finding.schema.json",
    "callchains": "callchain.schema.json",
    "requests": "http-request.schema.json",
    "evidence": "evidence.schema.json",
    "capabilities": "capability.schema.json",
    "mutations": "mutation.schema.json",
    "validationTasks": "validation-queue.schema.json",
    "attackChains": "attack-chain.schema.json",
    "reportModel": "report-model.schema.json",
    "decompilationPlan": "decompilation-plan.schema.json",
}


@dataclass
class Issue:
    severity: str
    category: str
    message: str
    path: str = ""
    expected: Any = None
    actual: Any = None
    fixable: bool = False
    auto_fixed: bool = False

    def to_json(self) -> dict[str, Any]:
        out = {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "fixable": self.fixable,
            "autoFixed": self.auto_fixed,
        }
        if self.path:
            out["path"] = self.path
        if self.expected is not None:
            out["expected"] = self.expected
        if self.actual is not None:
            out["actual"] = self.actual
        return out


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{idx}: invalid JSONL: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path}:{idx}: JSONL row must be object")
        rows.append(data)
    return rows


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: JSON document must be object")
    return data


def load_all(audit_dir: Path) -> dict[str, Any]:
    return {
        "project": load_json(audit_dir / "project.json"),
        "attackSurface": load_json(audit_dir / "attack_surface.json"),
        "findings": load_jsonl(audit_dir / "findings.jsonl"),
        "requests": load_jsonl(audit_dir / "requests.jsonl"),
        "callchains": load_jsonl(audit_dir / "callchains.jsonl"),
        "evidence": load_jsonl(audit_dir / "evidence.jsonl"),
        "capabilities": load_jsonl(audit_dir / "capabilities.jsonl"),
        "mutations": load_jsonl(audit_dir / "mutations.jsonl"),
        "attackChains": load_jsonl(audit_dir / "attack_chains.jsonl"),
        "validationTasks": load_jsonl(audit_dir / "validation_queue.jsonl"),
        "reportModel": load_json(audit_dir / "report_model.json"),
        "decompilationPlan": load_json(audit_dir / "decompilation_plan.json"),
    }


def by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("id", "")): row for row in rows if row.get("id")}


def schema_path(error_path: Any) -> str:
    parts = [str(part) for part in error_path]
    return ".".join(parts) if parts else "$"


def check_json_schema(data: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    if Draft202012Validator is None:
        return [Issue(
            "blocker",
            "missing-python-dependency",
            "jsonschema is required for Schema Gate",
            expected="python package jsonschema",
            actual="not installed",
        )]

    validators: dict[str, Any] = {}
    for key, filename in SCHEMA_FILES.items():
        schema = json.loads((SCHEMA_DIR / filename).read_text(encoding="utf-8"))
        validators[key] = Draft202012Validator(schema)

    for key in ("findings", "callchains", "requests", "evidence", "capabilities", "mutations", "validationTasks", "attackChains"):
        validator = validators[key]
        for idx, row in enumerate(data[key], 1):
            for error in sorted(validator.iter_errors(row), key=lambda item: list(item.path)):
                object_id = row.get("id") or row.get("taskId") or f"row-{idx}"
                issues.append(Issue(
                    "blocker",
                    "json-schema",
                    error.message,
                    f"{key}:{object_id}.{schema_path(error.path)}",
                ))

    for key, label in (("project", "project"), ("attackSurface", "attack_surface")):
        doc = data.get(key) or {}
        if doc:
            for error in sorted(validators[key].iter_errors(doc), key=lambda item: list(item.path)):
                issues.append(Issue(
                    "blocker",
                    "json-schema",
                    error.message,
                    f"{label}.{schema_path(error.path)}",
                ))

    report_model = data.get("reportModel") or {}
    if report_model:
        for error in sorted(validators["reportModel"].iter_errors(report_model), key=lambda item: list(item.path)):
            issues.append(Issue(
                "blocker",
                "json-schema",
                error.message,
                f"report_model.{schema_path(error.path)}",
            ))

    decompilation_plan = data.get("decompilationPlan") or {}
    if decompilation_plan:
        for error in sorted(validators["decompilationPlan"].iter_errors(decompilation_plan), key=lambda item: list(item.path)):
            issues.append(Issue(
                "blocker",
                "json-schema",
                error.message,
                f"decompilation_plan.{schema_path(error.path)}",
            ))

    return issues


def check_schema_like(data: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    findings = by_id(data["findings"])
    requests = by_id(data["requests"])
    callchains = by_id(data["callchains"])
    evidence = by_id(data["evidence"])
    capabilities = by_id(data["capabilities"])
    mutations = by_id(data["mutations"])
    attack_chains = by_id(data["attackChains"])
    validation_tasks = {str(row.get("taskId", "")): row for row in data["validationTasks"] if row.get("taskId")}
    report_model = data.get("reportModel") or {}
    mutations_by_finding: dict[str, list[dict[str, Any]]] = {}
    for mutation in mutations.values():
        mutations_by_finding.setdefault(str(mutation.get("findingId", "")), []).append(mutation)

    for finding_id, finding in findings.items():
        if not ID_PATTERNS["finding"].match(finding_id):
            issues.append(Issue("blocker", "invalid-id", "finding id does not match vul-NNN format", f"findings:{finding_id}.id", "vul-NNN", finding_id))
        status = finding.get("status")
        validation = finding.get("validationLevel")
        evidence_refs = finding.get("evidenceRefs") or []
        poc_refs = finding.get("pocRefs") or []
        call_chain = finding.get("callChain") or []

        if status == "confirmed" and validation not in ("V2", "V3", "V4"):
            issues.append(Issue("blocker", "status-validation-mismatch", "confirmed finding must be V2/V3/V4", f"findings:{finding_id}.validationLevel", "V2/V3/V4", validation))
        if status == "confirmed" and not evidence_refs:
            issues.append(Issue("blocker", "missing-evidence", "confirmed finding has no evidenceRefs", f"findings:{finding_id}.evidenceRefs"))
        if status == "confirmed" and not call_chain:
            issues.append(Issue("blocker", "missing-callchain", "confirmed finding has no callChain", f"findings:{finding_id}.callChain"))
        for callchain_id in call_chain:
            if callchain_id not in callchains:
                issues.append(Issue("blocker", "invalid-reference", "finding references missing callchain", f"findings:{finding_id}.callChain", "existing callchain id", callchain_id))
        if finding.get("entry", {}).get("type") == "http" and status == "confirmed" and not poc_refs:
            issues.append(Issue("blocker", "missing-poc", "confirmed HTTP finding has no pocRefs", f"findings:{finding_id}.pocRefs"))
        operation_classes = set(finding.get("operationClasses") or [])
        if status in ("confirmed", "reported", "patched") and operation_classes & {"write-capable", "state-changing", "destructive"}:
            finding_mutations = mutations_by_finding.get(finding_id, [])
            cleanup_refs = finding.get("cleanupRefs") or []
            has_cleanup_ref = bool(cleanup_refs)
            has_cleanup_mutation = any(
                mutation.get("cleanupRef") or mutation.get("cleanupUnavailableReason")
                for mutation in finding_mutations
            )
            if not has_cleanup_ref and not has_cleanup_mutation:
                issues.append(Issue(
                    "blocker",
                    "missing-cleanup",
                    "write/state-changing finding must have cleanup evidence or cleanupUnavailableReason",
                    f"findings:{finding_id}.cleanupRefs",
                    "cleanupRefs or mutation cleanupUnavailableReason",
                    cleanup_refs,
                ))

        for ev in evidence_refs:
            if ev not in evidence:
                issues.append(Issue("blocker", "invalid-reference", "finding references missing evidence", f"findings:{finding_id}.evidenceRefs", "existing evidence id", ev))
        for req in poc_refs:
            if req not in requests:
                issues.append(Issue("blocker", "invalid-reference", "finding references missing request", f"findings:{finding_id}.pocRefs", "existing request id", req))
        for cap in finding.get("requiresCapabilities") or []:
            if cap not in capabilities:
                issues.append(Issue("blocker", "invalid-reference", "finding requires missing capability", f"findings:{finding_id}.requiresCapabilities", "existing capability id", cap))

    for cap_id, cap in capabilities.items():
        if not ID_PATTERNS["capability"].match(cap_id):
            issues.append(Issue("blocker", "invalid-id", "capability id does not match cap-* format", f"capabilities:{cap_id}.id", "cap-*", cap_id))
        provider = cap.get("providerFinding")
        if provider not in findings:
            issues.append(Issue("blocker", "invalid-provider", "capability providerFinding does not exist", f"capabilities:{cap_id}.providerFinding", "existing finding id", provider))
        if cap.get("confidence") == "confirmed" and not cap.get("evidenceRefs"):
            issues.append(Issue("blocker", "missing-evidence", "confirmed capability has no evidenceRefs", f"capabilities:{cap_id}.evidenceRefs"))

    for task_id, task in validation_tasks.items():
        finding_id = task.get("findingId")
        if finding_id not in findings:
            issues.append(Issue("blocker", "invalid-reference", "validation task references missing finding", f"validationTasks:{task_id}.findingId", "existing finding id", finding_id))
        for provider_id in task.get("candidateProviders") or []:
            if provider_id not in capabilities:
                issues.append(Issue("blocker", "invalid-reference", "validation task references missing candidate provider", f"validationTasks:{task_id}.candidateProviders", "existing capability id", provider_id))

    for chain_id, chain in attack_chains.items():
        if not ID_PATTERNS["chain"].match(chain_id):
            issues.append(Issue("blocker", "invalid-id", "attack chain id does not match chain-* format", f"attackChains:{chain_id}.id", "chain-*", chain_id))
        node_ids = {str(node.get("id")) for node in chain.get("nodes") or []}
        for node in chain.get("nodes") or []:
            node_type = node.get("type")
            node_id = str(node.get("id"))
            if node_type == "finding" and node_id not in findings:
                issues.append(Issue("blocker", "invalid-reference", "attack chain references missing finding", f"attackChains:{chain_id}.nodes", "existing finding id", node_id))
            if node_type == "capability" and node_id not in capabilities:
                issues.append(Issue("blocker", "invalid-reference", "attack chain references missing capability", f"attackChains:{chain_id}.nodes", "existing capability id", node_id))
        for edge in chain.get("edges") or []:
            if edge.get("from") not in node_ids or edge.get("to") not in node_ids:
                issues.append(Issue("blocker", "invalid-reference", "attack chain edge endpoints must be chain nodes", f"attackChains:{chain_id}.edges"))
            for ev in edge.get("evidenceRefs") or []:
                if ev not in evidence:
                    issues.append(Issue("blocker", "invalid-reference", "attack chain edge references missing evidence", f"attackChains:{chain_id}.edges.evidenceRefs", "existing evidence id", ev))
        if chain.get("status") == "confirmed":
            for node in chain.get("nodes") or []:
                node_id = str(node.get("id"))
                if node.get("type") == "finding" and findings.get(node_id, {}).get("status") not in ("confirmed", "reported", "patched"):
                    issues.append(Issue("blocker", "unconfirmed-chain-node", "confirmed chain contains non-confirmed finding", f"attackChains:{chain_id}.nodes", "confirmed/reported/patched", node_id))
                if node.get("type") == "capability" and capabilities.get(node_id, {}).get("confidence") != "confirmed":
                    issues.append(Issue("blocker", "hypothesis-chain-node", "confirmed chain contains non-confirmed capability", f"attackChains:{chain_id}.nodes", "confirmed capability", node_id))

    if report_model:
        reported_findings = {str(fid) for fid in report_model.get("findings") or []}
        reported_chains = {str(chain_id) for chain_id in report_model.get("chains") or []}
        for fid in report_model.get("findings") or []:
            finding = findings.get(str(fid))
            if not finding:
                issues.append(Issue("blocker", "invalid-reference", "report model references missing finding", "report_model.findings", "existing finding id", fid))
                continue
            if finding.get("status") not in ("confirmed", "reported", "patched"):
                issues.append(Issue("blocker", "unconfirmed-report-finding", "report model includes non-reportable finding", f"report_model.findings:{fid}", "confirmed/reported/patched", finding.get("status")))
        for finding_id, finding in findings.items():
            if finding.get("status") in ("confirmed", "reported", "patched") and finding_id not in reported_findings:
                issues.append(Issue(
                    "blocker",
                    "report-omits-confirmed-finding",
                    "report model omits confirmed/reported/patched finding",
                    "report_model.findings",
                    "all reportable findings",
                    finding_id,
                ))
        for chain_id in report_model.get("chains") or []:
            if str(chain_id) not in attack_chains:
                issues.append(Issue("blocker", "invalid-reference", "report model references missing attack chain", "report_model.chains", "existing attack chain id", chain_id))
        for chain_id, chain in attack_chains.items():
            if chain.get("status") == "confirmed" and chain_id not in reported_chains:
                issues.append(Issue(
                    "blocker",
                    "report-omits-confirmed-chain",
                    "report model omits confirmed attack chain",
                    "report_model.chains",
                    "all confirmed chains",
                    chain_id,
                ))
        if report_model.get("evidencePolicy") != "full-internal-evidence-no-redaction":
            issues.append(Issue("blocker", "invalid-evidence-policy", "report model must preserve full internal evidence", "report_model.evidencePolicy", "full-internal-evidence-no-redaction", report_model.get("evidencePolicy")))

    project = data.get("project") or {}
    decompilation = project.get("decompilation") or {}
    decompilation_plan = data.get("decompilationPlan") or {}
    if decompilation.get("required") is True and not decompilation_plan:
        issues.append(Issue(
            "blocker",
            "missing-decompilation-plan",
            "project requires decompilation but decompilation_plan.json is missing",
            "decompilation_plan.json",
        ))
    for task in decompilation_plan.get("tasks") or []:
        if not task.get("artifactSha256"):
            issues.append(Issue(
                "warning",
                "decompilation-artifact-hash-missing",
                "decompilation task has no artifactSha256",
                f"decompilation_plan.tasks:{task.get('taskId')}.artifactSha256",
            ))
        if task.get("status") != "completed":
            issues.append(Issue(
                "warning",
                "decompilation-not-complete",
                "decompilation task is not completed",
                f"decompilation_plan.tasks:{task.get('taskId')}.status",
                "completed",
                task.get("status"),
            ))

    return issues


def check_semantic(data: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    findings = by_id(data["findings"])
    requests = by_id(data["requests"])
    capabilities = by_id(data["capabilities"])

    for finding_id, finding in findings.items():
        impacts = finding.get("impacts") or {}
        vector = (finding.get("cvss") or {}).get("vector", "")
        auth = finding.get("authLevel")

        expected_tokens = {
            "confidentiality": ("/C:H", "C"),
            "integrity": ("/I:H", "I"),
            "availability": ("/A:H", "A"),
        }
        for key, (token, metric) in expected_tokens.items():
            if impacts.get(key) == "high" and token not in vector:
                issues.append(Issue("blocker", "cvss-impact-mismatch", f"impact {key}=high but CVSS {metric} is not H", f"findings:{finding_id}.cvss.vector", token, vector))

        if auth == "none" and "/PR:N" not in vector:
            issues.append(Issue("blocker", "cvss-auth-mismatch", "authLevel none should map to PR:N", f"findings:{finding_id}.cvss.vector", "PR:N", vector))
        if auth == "low-privileged" and "/PR:L" not in vector:
            issues.append(Issue("warning", "cvss-auth-mismatch", "authLevel low-privileged usually maps to PR:L", f"findings:{finding_id}.cvss.vector", "PR:L", vector))

        for req_id in finding.get("pocRefs") or []:
            req = requests.get(req_id)
            if not req:
                continue
            if auth == "none" and req.get("purpose") in ("exploit", "proof") and req.get("authUsage") != "none":
                issues.append(Issue("blocker", "auth-poc-mismatch", "finding authLevel is none but exploit/proof request uses authentication", f"requests:{req_id}.authUsage", "none", req.get("authUsage")))

        for cap_id in finding.get("requiresCapabilities") or []:
            cap = capabilities.get(cap_id)
            if cap and finding.get("status") == "confirmed" and cap.get("confidence") != "confirmed":
                issues.append(Issue("blocker", "hypothesis-capability-used", "confirmed finding depends on non-confirmed capability", f"findings:{finding_id}.requiresCapabilities", "confirmed capability", cap_id))

    return issues


def check_poc(data: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    requests = by_id(data["requests"])

    for req_id, req in requests.items():
        raw = str(req.get("raw", ""))
        lines = raw.replace("\r\n", "\n").split("\n")
        first = lines[0] if lines else ""

        if not HTTP_REQUEST_LINE.match(first):
            issues.append(Issue("blocker", "invalid-http-request-line", "raw HTTP request line is invalid", f"requests:{req_id}.raw", "METHOD /path HTTP/1.1", first))
        if not any(line.lower().startswith("host:") for line in lines):
            issues.append(Issue("blocker", "missing-host", "raw HTTP request has no Host header", f"requests:{req_id}.raw"))
        if "\n\n" not in raw.replace("\r\n", "\n"):
            issues.append(Issue("error", "missing-header-body-separator", "raw HTTP request should contain a blank line between headers and body", f"requests:{req_id}.raw"))

        for pattern in BAD_PLACEHOLDER_PATTERNS:
            match = re.search(pattern, raw, flags=re.I)
            if match:
                issues.append(Issue("blocker", "bad-placeholder", f"raw HTTP request contains forbidden placeholder: {match.group(0)}", f"requests:{req_id}.raw", "bound variable with provider or concrete value", match.group(0)))

        if "..." in raw:
            issues.append(Issue("blocker", "payload-ellipsis", "raw HTTP request contains ellipsis in payload/request", f"requests:{req_id}.raw"))

        declared_vars = {var.get("name") for var in req.get("variables") or [] if isinstance(var, dict)}
        for var_name in BOUND_VARIABLE.findall(raw):
            if var_name not in declared_vars:
                issues.append(Issue("blocker", "unbound-variable", "bound variable appears in raw request but is not declared", f"requests:{req_id}.variables", "declared variable provider", var_name))
        for var in req.get("variables") or []:
            provider = var.get("providedBy")
            if provider and provider not in requests:
                issues.append(Issue("blocker", "missing-variable-provider", "bound variable provider request does not exist", f"requests:{req_id}.variables", "existing request id", provider))

    return issues


def check_render(audit_dir: Path, data: dict[str, Any], require_report: bool) -> list[Issue]:
    issues: list[Issue] = []
    report_path = audit_dir / "reports" / "security_audit_report.md"
    report_model = data.get("reportModel") or {}
    if not report_path.exists():
        if require_report and report_model:
            issues.append(Issue("blocker", "missing-rendered-report", "rendered report is missing", str(report_path)))
        return issues

    text = report_path.read_text(encoding="utf-8")
    if text.count("```") % 2 != 0:
        issues.append(Issue("blocker", "unbalanced-code-fence", "rendered report has unbalanced code fences", str(report_path)))
    for pattern in BAD_PLACEHOLDER_PATTERNS:
        match = re.search(pattern, text, flags=re.I)
        if match:
            issues.append(Issue("blocker", "bad-placeholder", f"rendered report contains forbidden placeholder: {match.group(0)}", str(report_path)))
    if "..." in text:
        issues.append(Issue("warning", "report-ellipsis", "rendered report contains ellipsis; verify it is not hiding PoC or evidence", str(report_path)))
    for marker in ("缺失 finding", "缺失请求", "缺失证据", "缺失结构化链"):
        if marker in text:
            issues.append(Issue("blocker", "render-missing-reference", f"rendered report contains missing-reference marker: {marker}", str(report_path)))
    for fid in report_model.get("findings") or []:
        if str(fid) not in text:
            issues.append(Issue("blocker", "render-omits-finding", "rendered report omits report model finding", str(report_path), "finding id in report", fid))
    for chain_id in report_model.get("chains") or []:
        if str(chain_id) not in text:
            issues.append(Issue("blocker", "render-omits-chain", "rendered report omits report model chain", str(report_path), "chain id in report", chain_id))
    return issues


def build_result(gate: str, audit_dir: Path, issues: list[Issue]) -> dict[str, Any]:
    summary = {"blocker": 0, "error": 0, "warning": 0, "info": 0}
    for issue in issues:
        summary[issue.severity] += 1
    if summary["blocker"]:
        code, reason = 2, "blocker_found"
    elif summary["error"]:
        code, reason = 1, "error_found"
    else:
        code, reason = 0, "ok"
    return {
        "schemaVersion": "quality-result/v1",
        "runId": "qr-local",
        "gate": gate,
        "target": str(audit_dir),
        "summary": summary,
        "issues": [issue.to_json() for issue in issues],
        "exit": {"code": code, "reason": reason},
    }


def run_gate(audit_dir: Path, gate: str) -> dict[str, Any]:
    data = load_all(audit_dir)
    issues: list[Issue] = []
    if gate in ("schema", "all"):
        issues.extend(check_json_schema(data))
        issues.extend(check_schema_like(data))
    if gate in ("semantic", "all"):
        issues.extend(check_semantic(data))
    if gate in ("poc", "all"):
        issues.extend(check_poc(data))
    if gate in ("render", "all"):
        issues.extend(check_render(audit_dir, data, require_report=gate == "render"))
    return build_result(gate, audit_dir, issues)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run quality gates")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--gate", choices=["schema", "semantic", "poc", "render", "all"], default="all")
    args = parser.parse_args(argv)

    try:
        result = run_gate(Path(args.audit_dir), args.gate)
    except Exception as exc:
        result = {
            "schemaVersion": "quality-result/v1",
            "runId": "qr-local",
            "gate": args.gate,
            "target": args.audit_dir,
            "summary": {"blocker": 1, "error": 0, "warning": 0, "info": 0},
            "issues": [{
                "severity": "blocker",
                "category": "quality-gate-crash",
                "message": str(exc),
                "fixable": False,
                "autoFixed": False,
            }],
            "exit": {"code": 3, "reason": "quality_gate_crash"},
        }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result["exit"]["code"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
