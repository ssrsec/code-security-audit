#!/usr/bin/env python3
"""Replay raw HTTP requests for authorized validation.

Default mode is dry-run. Network execution requires --execute. L2 and L3
requests require explicit allow flags.
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            rows.append(json.loads(text))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def parse_raw_http(raw: str) -> dict[str, Any]:
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    if not lines:
        raise ValueError("empty raw HTTP request")
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise ValueError(f"invalid request line: {request_line}")
    method, path, _version = parts
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError(f"invalid header line: {line}")
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    if "Host" not in headers and "host" not in {key.lower(): value for key, value in headers.items()}:
        raise ValueError("missing Host header")
    return {
        "method": method.upper(),
        "path": path,
        "headers": headers,
        "body": body.encode("utf-8"),
    }


def host_header(headers: dict[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "host":
            return value
    raise ValueError("missing Host header")


def target_from_request(req: dict[str, Any], parsed: dict[str, Any], base_url: str | None) -> tuple[str, str, int, str]:
    if base_url:
        url = urlparse(base_url)
        scheme = url.scheme or "http"
        host = url.hostname or host_header(parsed["headers"])
        port = url.port or (443 if scheme == "https" else 80)
        prefix = url.path.rstrip("/")
        path = prefix + parsed["path"] if prefix else parsed["path"]
        return scheme, host, port, path
    host = host_header(parsed["headers"])
    if ":" in host:
        name, port_text = host.rsplit(":", 1)
        return "http", name, int(port_text), parsed["path"]
    return "http", host, 80, parsed["path"]


def allowed_safe_level(req: dict[str, Any], allow_l2: bool, allow_l3: bool) -> tuple[bool, str]:
    level = req.get("safeLevel", "L1")
    if level == "L1":
        return True, "allowed"
    if level == "L2" and allow_l2:
        return True, "allowed-l2"
    if level == "L3" and allow_l3:
        return True, "allowed-l3"
    return False, f"{level} requires explicit approval"


def execute_request(req: dict[str, Any], base_url: str | None, timeout: float, insecure_tls: bool) -> dict[str, Any]:
    parsed = parse_raw_http(str(req.get("raw", "")))
    scheme, host, port, path = target_from_request(req, parsed, base_url)
    headers = dict(parsed["headers"])
    headers.pop("Host", None)
    headers.pop("host", None)
    if scheme == "https":
        context = ssl._create_unverified_context() if insecure_tls else None
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request(parsed["method"], path, body=parsed["body"], headers=headers)
    response = conn.getresponse()
    body = response.read(4096)
    conn.close()
    text = body.decode("utf-8", errors="replace")
    return {
        "statusCode": response.status,
        "responseSnippet": text,
        "environmentFingerprint": {
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
        },
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Replay HTTP requests")
    parser.add_argument("--audit-dir", default="audit-v2")
    parser.add_argument("--requests-file")
    parser.add_argument("--base-url", help="override scheme/host/optional path prefix")
    parser.add_argument("--execute", action="store_true", help="perform network requests")
    parser.add_argument("--allow-l2", action="store_true", help="allow reversible-write requests")
    parser.add_argument("--allow-l3", action="store_true", help="allow destructive requests")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--insecure-tls", action="store_true")
    parser.add_argument("--evidence-output")
    args = parser.parse_args(argv)

    audit_dir = Path(args.audit_dir)
    requests_file = Path(args.requests_file) if args.requests_file else audit_dir / "requests.jsonl"
    requests = load_jsonl(requests_file)
    evidence_rows: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    exit_code = 0

    for idx, req in enumerate(requests, 1):
        allowed, reason = allowed_safe_level(req, args.allow_l2, args.allow_l3)
        parsed_error = None
        try:
            parsed = parse_raw_http(str(req.get("raw", "")))
        except Exception as exc:
            parsed = {}
            parsed_error = str(exc)
            exit_code = 2

        item = {
            "requestId": req.get("id"),
            "findingId": req.get("findingId"),
            "safeLevel": req.get("safeLevel", "L1"),
            "execute": bool(args.execute and allowed and parsed and not parsed_error),
            "allowed": allowed,
            "reason": reason if not parsed_error else parsed_error,
        }

        if args.execute and allowed and not parsed_error:
            try:
                executed = execute_request(req, args.base_url, args.timeout, args.insecure_tls)
                item.update(executed)
                evidence_rows.append({
                    "schemaVersion": "evidence/v1",
                    "id": f"ev-replay-{idx:04d}",
                    "findingId": req["findingId"],
                    "requestRef": req["id"],
                    "environment": "live-target",
                    "executedAt": now(),
                    "statusCode": executed["statusCode"],
                    "responseSnippet": executed["responseSnippet"],
                    "environmentFingerprint": executed["environmentFingerprint"],
                    "assertions": [{
                        "type": "status-code",
                        "expected": "HTTP response received",
                        "actual": executed["statusCode"],
                        "passed": 100 <= int(executed["statusCode"]) <= 599,
                    }],
                    "limitations": [],
                })
            except Exception as exc:
                item["error"] = str(exc)
                exit_code = 2
        elif args.execute and not allowed:
            exit_code = 2

        results.append(item)

    if evidence_rows:
        output = Path(args.evidence_output) if args.evidence_output else audit_dir / "evidence.replay.jsonl"
        write_jsonl(output, evidence_rows)
    else:
        output = None

    print(json.dumps({
        "ok": exit_code == 0,
        "mode": "execute" if args.execute else "dry-run",
        "requests": len(requests),
        "results": results,
        "evidenceOutput": str(output) if output else None,
    }, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
