#!/usr/bin/env python3
"""
Knowledge base query tool.
Searches knowledge files by keywords, CWE, OWASP, framework, or vuln_type.
Used by audit-validate-agent to auto-locate relevant knowledge documents.

Usage:
  python3 knowledge_query.py --keyword "SQL注入"
  python3 knowledge_query.py --cwe CWE-89
  python3 knowledge_query.py --owasp A03:2021
  python3 knowledge_query.py --framework Java
  python3 knowledge_query.py --vuln-type deserialization
  python3 knowledge_query.py --query "Fastjson autoType RCE"  # multi-keyword fuzzy
"""
import argparse
import json
import os
import re
import sys

import yaml

KNOWLEDGE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "skills", "audit-validate", "resources", "knowledge"
)


def load_index():
    """Load YAML frontmatter from all knowledge files."""
    index = {}
    for root, _, files in os.walk(KNOWLEDGE_DIR):
        for f in files:
            if not f.endswith('.md') or f == 'README.md':
                continue
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    content = fh.read()
                if content.startswith('---'):
                    parts = content.split('---', 2)
                    if len(parts) >= 3:
                        meta = yaml.safe_load(parts[1]) or {}
                        rel = os.path.relpath(path, KNOWLEDGE_DIR)
                        index[rel] = meta
            except Exception:
                continue
    return index


def search(index, keyword=None, cwe=None, owasp=None, framework=None, vuln_type=None, query=None):
    """Search knowledge index. Returns list of (file, score, meta)."""
    results = []
    for fname, meta in index.items():
        score = 0
        reasons = []

        if keyword:
            kw_lower = keyword.lower()
            for k in meta.get('keywords', []):
                if kw_lower in str(k).lower():
                    score += 10
                    reasons.append(f"keyword:{k}")

        if cwe:
            if cwe.upper() in [c.upper() for c in meta.get('cwe', [])]:
                score += 20
                reasons.append(f"cwe:{cwe}")

        if owasp:
            if owasp in meta.get('owasp', []):
                score += 15
                reasons.append(f"owasp:{owasp}")

        if framework:
            fw_lower = framework.lower()
            for fw in meta.get('frameworks', []):
                if fw_lower in fw.lower() or fw == '*':
                    score += 5
                    reasons.append(f"framework:{fw}")
                    break

        if vuln_type:
            vt_lower = vuln_type.lower()
            for vt in meta.get('vuln_types', []):
                if vt_lower in vt.lower() or vt.lower() in vt_lower:
                    score += 15
                    reasons.append(f"vuln_type:{vt}")

        if query:
            tokens = re.split(r'[\s,]+', query.lower())
            for token in tokens:
                if len(token) < 2:
                    continue
                for k in meta.get('keywords', []):
                    if token in str(k).lower():
                        score += 3
                        reasons.append(f"query_hit:{k}")
                        break
                for vt in meta.get('vuln_types', []):
                    if token in vt.lower():
                        score += 3
                        break

        if score > 0:
            results.append((fname, score, reasons, meta))

    results.sort(key=lambda x: -x[1])
    return results


def main():
    parser = argparse.ArgumentParser(description='Query knowledge base')
    parser.add_argument('--keyword', '-k', help='Search by keyword')
    parser.add_argument('--cwe', '-c', help='Search by CWE ID (e.g., CWE-89)')
    parser.add_argument('--owasp', '-o', help='Search by OWASP (e.g., A03:2021)')
    parser.add_argument('--framework', '-f', help='Filter by framework (e.g., Java)')
    parser.add_argument('--vuln-type', '-v', help='Search by vulnerability type')
    parser.add_argument('--query', '-q', help='Multi-keyword fuzzy query')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--top', type=int, default=5, help='Max results (default: 5)')
    args = parser.parse_args()

    if not any([args.keyword, args.cwe, args.owasp, args.framework, args.vuln_type, args.query]):
        parser.print_help()
        sys.exit(1)

    index = load_index()
    results = search(
        index,
        keyword=args.keyword,
        cwe=args.cwe,
        owasp=args.owasp,
        framework=args.framework,
        vuln_type=args.vuln_type,
        query=args.query
    )[:args.top]

    if args.json:
        output = [{"file": r[0], "score": r[1], "reasons": r[2]} for r in results]
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        if not results:
            print("No matching knowledge documents found.")
            return
        print(f"Found {len(results)} matching documents:\n")
        for fname, score, reasons, meta in results:
            print(f"  📄 {fname} (score: {score})")
            print(f"     CWE: {', '.join(meta.get('cwe', []))}")
            print(f"     OWASP: {', '.join(meta.get('owasp', []))}")
            print(f"     Frameworks: {', '.join(meta.get('frameworks', []))}")
            print(f"     Match: {', '.join(reasons[:5])}")
            print()


if __name__ == '__main__':
    main()
