#!/usr/bin/env python3
"""
审计报告质量自检脚本。
Phase 6 报告生成后由 orchestrator 自动调用，检查常见质量问题。
用法: python3 scripts/quality_check.py audit/
"""
import re
import sys
from pathlib import Path


def check_report(audit_dir: str) -> list[dict]:
    issues = []
    audit_path = Path(audit_dir)

    report_file = audit_path / "security_audit_report.md"
    if not report_file.exists():
        issues.append({"severity": "CRITICAL", "msg": "主报告文件不存在"})
        return issues

    report = report_file.read_text(encoding="utf-8")

    placeholders = [
        r"REPLACE_\w+", r"YOUR_HOST", r"YOUR_\w+",
        r"此处从略", r"从略", r"细节略", r"不再展开",
        r"需按目标.*编写", r"<!-- .*替换.*-->", r"<root\s*/>",
    ]
    for pat in placeholders:
        matches = re.findall(pat, report)
        if matches:
            issues.append({
                "severity": "HIGH",
                "msg": f"发现禁止占位符: {matches[0]} (共 {len(matches)} 处)"
            })

    vul_headers = re.findall(r"vul-\d+", report)
    cvss_vectors = re.findall(
        r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]",
        report
    )
    if len(vul_headers) > 0 and len(cvss_vectors) < len(set(vul_headers)):
        issues.append({
            "severity": "MEDIUM",
            "msg": f"漏洞数 {len(set(vul_headers))} 但完整 CVSS 向量只有 {len(cvss_vectors)} 个"
        })

    fuzzy_cvss = re.findall(r"CVSS.*[约≈大约]", report)
    if fuzzy_cvss:
        issues.append({
            "severity": "HIGH",
            "msg": f"CVSS 使用模糊词: {fuzzy_cvss[0]}"
        })

    vul_nums = sorted(set(int(re.search(r"\d+", v).group()) for v in vul_headers))
    if vul_nums:
        expected = list(range(1, max(vul_nums) + 1))
        missing = set(expected) - set(vul_nums)
        if missing:
            issues.append({
                "severity": "LOW",
                "msg": f"漏洞编号不连续，缺失: {sorted(missing)}"
            })

    file_refs = re.findall(
        r"(\S+\.(?:java|py|go|cs|js|ts|php|rb|jsp|xml|yaml|yml|json|config|properties)):(\d+)",
        report
    )
    missing_files = []
    for filepath, _ in file_refs[:20]:
        full_path = audit_path.parent / filepath
        decompiled_path = audit_path / "decompiled" / filepath
        if not full_path.exists() and not decompiled_path.exists():
            if not any((audit_path.parent / p / filepath).exists()
                      for p in ["", "src", "src/main/java"]):
                missing_files.append(filepath)

    if missing_files:
        issues.append({
            "severity": "MEDIUM",
            "msg": f"引用文件可能不存在: {missing_files[:5]}"
        })

    findings_dir = audit_path / "findings"
    if findings_dir.exists():
        finding_files = list(findings_dir.glob("vul-*.md"))
        if finding_files:
            for ff in finding_files:
                content = ff.read_text(encoding="utf-8")
                if len(content.strip()) < 100:
                    issues.append({
                        "severity": "HIGH",
                        "msg": f"分文件 {ff.name} 内容过短（可能未完整生成）"
                    })

    code_blocks = re.findall(r"```[\s\S]*?```", report)
    for i, block in enumerate(code_blocks):
        if "..." in block and "# ..." not in block:
            if "import" in block or "def " in block or "curl" in block:
                issues.append({
                    "severity": "MEDIUM",
                    "msg": f"代码块 #{i+1} 中发现省略号，可能不完整"
                })
                break

    required_sections = ["一、", "二、", "三、", "四、", "五、"]
    for section in required_sections:
        if section not in report:
            issues.append({
                "severity": "HIGH",
                "msg": f"缺少必要章节: {section}"
            })

    comp_refs = re.findall(r"comp-\d+", report)
    for comp_ref in comp_refs:
        vul_refs_in_comp = re.findall(
            rf"{comp_ref}.*?(vul-\d+)", report, re.DOTALL
        )
        for vr in vul_refs_in_comp:
            if vr not in vul_headers:
                issues.append({
                    "severity": "HIGH",
                    "msg": f"组合漏洞 {comp_ref} 引用了不存在的 {vr}"
                })

    vf_path = audit_path / "phase4" / "validated_findings.md"
    if vf_path.exists():
        vf_content = vf_path.read_text(encoding="utf-8")
        vf_vuls = set(re.findall(r"vul-\d+", vf_content))
        report_vuls = set(vul_headers)
        dropped = vf_vuls - report_vuls
        if dropped:
            issues.append({
                "severity": "HIGH",
                "msg": f"validated_findings 中有漏洞未进入报告: {sorted(dropped)}"
            })

    return issues


def check_phase4(audit_dir: str) -> list[dict]:
    """Phase 4 产出质量检查（在 Phase 4 完成后、Phase 5 前调用）。"""
    issues = []
    audit_path = Path(audit_dir)

    vf_path = audit_path / "phase4" / "validated_findings.md"
    if not vf_path.exists():
        issues.append({"severity": "CRITICAL", "msg": "validated_findings.md 不存在"})
        return issues

    vf = vf_path.read_text(encoding="utf-8")

    vul_ids = re.findall(r"vul-\d+", vf)
    if not vul_ids:
        issues.append({"severity": "MEDIUM", "msg": "validated_findings.md 中未找到 vul-NNN 编号"})

    for pat in [r"REPLACE_\w+", r"YOUR_HOST", r"此处从略", r"<root\s*/>"]:
        matches = re.findall(pat, vf)
        if matches:
            issues.append({
                "severity": "HIGH",
                "msg": f"Phase 4 产出存在占位符: {matches[0]}"
            })

    cvss_count = len(re.findall(
        r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]",
        vf
    ))
    unique_vuls = len(set(vul_ids))
    if unique_vuls > 0 and cvss_count < unique_vuls:
        issues.append({
            "severity": "MEDIUM",
            "msg": f"Phase 4: {unique_vuls} 条漏洞但只有 {cvss_count} 个 CVSS 向量"
        })

    return issues


def main():
    audit_dir = sys.argv[1] if len(sys.argv) > 1 else "audit/"
    mode = sys.argv[2] if len(sys.argv) > 2 else "report"

    if mode == "phase4":
        issues = check_phase4(audit_dir)
        label = "Phase 4 产出"
    else:
        issues = check_report(audit_dir)
        label = "最终报告"

    if not issues:
        print(f"✅ {label}质量检查通过，未发现问题。")
        return 0

    print(f"⚠️ {label}发现 {len(issues)} 个质量问题:\n")
    for i, issue in enumerate(issues, 1):
        print(f"  [{issue['severity']}] {i}. {issue['msg']}")

    critical_count = sum(1 for i in issues if i["severity"] in ("CRITICAL", "HIGH"))
    if critical_count > 0:
        print(f"\n❌ 有 {critical_count} 个高严重度问题，需要修复后再交付。")
        return 1
    else:
        print("\n⚠️ 存在中低严重度问题，建议修复。")
        return 0


if __name__ == "__main__":
    sys.exit(main())
