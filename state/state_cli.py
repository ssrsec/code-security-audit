#!/usr/bin/env python3
"""SQLite state utility for code-security-audit v2."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema)
    conn.commit()


def write_event(
    conn: sqlite3.Connection,
    project_id: str,
    event_type: str,
    message: str,
    *,
    severity: str = "info",
    object_type: str | None = None,
    object_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO events (
          project_id, event_type, severity, object_type, object_id,
          message, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            event_type,
            severity,
            object_type,
            object_id,
            message,
            json.dumps(payload or {}, ensure_ascii=False, sort_keys=True),
            now(),
        ),
    )


def cmd_init(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    with connect(db_path) as conn:
        init_db(conn)
        ts = now()
        conn.execute(
            """
            INSERT INTO projects (
              id, root_path, audit_mode, source_shape, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              root_path=excluded.root_path,
              audit_mode=excluded.audit_mode,
              source_shape=excluded.source_shape,
              updated_at=excluded.updated_at
            """,
            (
                args.project_id,
                str(Path(args.project_root).resolve()),
                args.audit_mode,
                args.source_shape,
                "initialized",
                ts,
                ts,
            ),
        )
        write_event(
            conn,
            args.project_id,
            "project.initialized",
            "audit state initialized",
            object_type="project",
            object_id=args.project_id,
            payload={
                "projectRoot": str(Path(args.project_root).resolve()),
                "auditMode": args.audit_mode,
                "sourceShape": args.source_shape,
            },
        )
        conn.commit()
    print(json.dumps({"ok": True, "db": str(db_path), "projectId": args.project_id}, ensure_ascii=False))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    if not db_path.exists():
        print(json.dumps({"ok": False, "error": "state database not found", "db": str(db_path)}, ensure_ascii=False))
        return 2
    with connect(db_path) as conn:
        projects = [dict(row) for row in conn.execute("SELECT * FROM projects ORDER BY created_at").fetchall()]
        counts = {}
        for table in (
            "events",
            "workers",
            "intents",
            "findings",
            "callchains",
            "requests",
            "evidence",
            "capabilities",
            "mutations",
            "validation_tasks",
            "decompilation_tasks",
            "attack_chains",
            "quality_results",
            "report_models",
        ):
            counts[table] = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
    print(json.dumps({"ok": True, "db": str(db_path), "projects": projects, "counts": counts}, ensure_ascii=False, indent=2))
    return 0


def cmd_add_event(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    with connect(db_path) as conn:
        init_db(conn)
        payload = json.loads(args.payload) if args.payload else {}
        write_event(
            conn,
            args.project_id,
            args.event_type,
            args.message,
            severity=args.severity,
            object_type=args.object_type,
            object_id=args.object_id,
            payload=payload,
        )
        conn.commit()
    print(json.dumps({"ok": True}, ensure_ascii=False))
    return 0


def cmd_export_events(args: argparse.Namespace) -> int:
    audit_dir = Path(args.audit_dir)
    db_path = audit_dir / "state.sqlite"
    output = Path(args.output) if args.output else audit_dir / "events.jsonl"
    if not db_path.exists():
        print(json.dumps({"ok": False, "error": "state database not found", "db": str(db_path)}, ensure_ascii=False))
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as conn, output.open("w", encoding="utf-8") as fh:
        rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        for row in rows:
            item = dict(row)
            if item.get("payload_json"):
                item["payload"] = json.loads(item.pop("payload_json"))
            fh.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    print(json.dumps({"ok": True, "output": str(output), "events": len(rows)}, ensure_ascii=False))
    return 0


def iter_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{idx}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path}:{idx}: row must be JSON object")
        rows.append(data)
    return rows


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: document must be JSON object")
    return data


def cmd_import_jsonl(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    source = Path(args.file)
    if not source.exists():
        print(json.dumps({"ok": False, "error": "input file not found", "file": str(source)}, ensure_ascii=False))
        return 2
    rows = iter_jsonl(source)
    with connect(db_path) as conn:
        init_db(conn)
        imported = 0
        for row in rows:
            if args.kind == "findings":
                finding_id = row["id"]
                conn.execute(
                    """
                    INSERT INTO findings (
                      id, project_id, status, category, severity, validation_level,
                      auth_level, title, data_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      status=excluded.status,
                      category=excluded.category,
                      severity=excluded.severity,
                      validation_level=excluded.validation_level,
                      auth_level=excluded.auth_level,
                      title=excluded.title,
                      data_json=excluded.data_json,
                      updated_at=excluded.updated_at
                    """,
                    (
                        finding_id,
                        args.project_id,
                        row.get("status", "candidate"),
                        row.get("category", "injection"),
                        row.get("severity", "medium"),
                        row.get("validationLevel", "V0"),
                        row.get("authLevel", "unknown"),
                        row.get("title", finding_id),
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                        now(),
                    ),
                )
                for source_id in row.get("sourceIds") or []:
                    conn.execute(
                        "INSERT OR IGNORE INTO finding_sources (finding_id, source_id) VALUES (?, ?)",
                        (finding_id, source_id),
                    )
                write_event(conn, args.project_id, "finding.imported", f"imported finding {finding_id}", object_type="finding", object_id=finding_id)
            elif args.kind == "callchains":
                callchain_id = row["id"]
                conn.execute(
                    """
                    INSERT INTO callchains (
                      id, finding_id, data_json, created_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      finding_id=excluded.finding_id,
                      data_json=excluded.data_json
                    """,
                    (
                        callchain_id,
                        row["findingId"],
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "callchain.imported", f"imported callchain {callchain_id}", object_type="callchain", object_id=callchain_id)
            elif args.kind == "requests":
                req_id = row["id"]
                conn.execute(
                    """
                    INSERT INTO requests (
                      id, finding_id, purpose, auth_usage, raw, data_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      purpose=excluded.purpose,
                      auth_usage=excluded.auth_usage,
                      raw=excluded.raw,
                      data_json=excluded.data_json
                    """,
                    (
                        req_id,
                        row["findingId"],
                        row.get("purpose", "proof"),
                        row.get("authUsage", "none"),
                        row.get("raw", ""),
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "request.imported", f"imported request {req_id}", object_type="request", object_id=req_id)
            elif args.kind == "evidence":
                ev_id = row["id"]
                conn.execute(
                    """
                    INSERT INTO evidence (
                      id, finding_id, request_id, environment, data_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      request_id=excluded.request_id,
                      environment=excluded.environment,
                      data_json=excluded.data_json
                    """,
                    (
                        ev_id,
                        row["findingId"],
                        row.get("requestRef"),
                        row.get("environment", "static"),
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "evidence.imported", f"imported evidence {ev_id}", object_type="evidence", object_id=ev_id)
            elif args.kind == "capabilities":
                cap_id = row["id"]
                conn.execute(
                    """
                    INSERT INTO capabilities (
                      id, project_id, provider_finding_id, name, confidence,
                      operation_class, data_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      provider_finding_id=excluded.provider_finding_id,
                      name=excluded.name,
                      confidence=excluded.confidence,
                      operation_class=excluded.operation_class,
                      data_json=excluded.data_json
                    """,
                    (
                        cap_id,
                        args.project_id,
                        row["providerFinding"],
                        row.get("name", cap_id),
                        row.get("confidence", "hypothesis"),
                        row.get("operationClass", "unknown"),
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "capability.imported", f"imported capability {cap_id}", object_type="capability", object_id=cap_id)
            elif args.kind == "mutations":
                mutation_id = row["id"]
                conn.execute(
                    """
                    INSERT INTO mutations (
                      id, finding_id, operation_level, mutation_type, data_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      finding_id=excluded.finding_id,
                      operation_level=excluded.operation_level,
                      mutation_type=excluded.mutation_type,
                      data_json=excluded.data_json
                    """,
                    (
                        mutation_id,
                        row["findingId"],
                        row.get("operationLevel", "L1"),
                        row.get("mutationType", "db-update"),
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "mutation.imported", f"imported mutation {mutation_id}", object_type="mutation", object_id=mutation_id)
            elif args.kind == "validation-tasks":
                task_id = row["taskId"]
                conn.execute(
                    """
                    INSERT INTO validation_tasks (
                      id, finding_id, priority, status, safe_level, blocker_type,
                      next_action, data_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      finding_id=excluded.finding_id,
                      priority=excluded.priority,
                      status=excluded.status,
                      safe_level=excluded.safe_level,
                      blocker_type=excluded.blocker_type,
                      next_action=excluded.next_action,
                      data_json=excluded.data_json,
                      updated_at=excluded.updated_at
                    """,
                    (
                        task_id,
                        row["findingId"],
                        row.get("priority", "P2"),
                        row.get("status", "pending"),
                        row.get("safeLevel", "L1"),
                        row.get("blockerType", "none"),
                        row.get("nextAction", ""),
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "validation_task.imported", f"imported validation task {task_id}", object_type="validation_task", object_id=task_id)
            elif args.kind == "attack-chains":
                chain_id = row["id"]
                conn.execute(
                    """
                    INSERT INTO attack_chains (
                      id, project_id, status, chain_type, data_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      status=excluded.status,
                      chain_type=excluded.chain_type,
                      data_json=excluded.data_json,
                      updated_at=excluded.updated_at
                    """,
                    (
                        chain_id,
                        args.project_id,
                        row.get("status", "hypothesis"),
                        row.get("chainType", "mixed"),
                        json.dumps(row, ensure_ascii=False, sort_keys=True),
                        now(),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "attack_chain.imported", f"imported attack chain {chain_id}", object_type="attack_chain", object_id=chain_id)
            else:
                raise ValueError(f"unsupported kind: {args.kind}")
            imported += 1
        conn.commit()
    print(json.dumps({"ok": True, "kind": args.kind, "imported": imported}, ensure_ascii=False))
    return 0


def cmd_import_json(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    source = Path(args.file)
    if not source.exists():
        print(json.dumps({"ok": False, "error": "input file not found", "file": str(source)}, ensure_ascii=False))
        return 2
    row = load_json(source)
    with connect(db_path) as conn:
        init_db(conn)
        if args.kind == "quality-result":
            result_id = row.get("runId", "qr-local")
            conn.execute(
                """
                INSERT INTO quality_results (
                  id, project_id, gate, exit_code, data_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  gate=excluded.gate,
                  exit_code=excluded.exit_code,
                  data_json=excluded.data_json
                """,
                (
                    result_id,
                    args.project_id,
                    row.get("gate", "all"),
                    int((row.get("exit") or {}).get("code", 3)),
                    json.dumps(row, ensure_ascii=False, sort_keys=True),
                    now(),
                ),
            )
            write_event(conn, args.project_id, "quality_result.imported", f"imported quality result {result_id}", object_type="quality_result", object_id=result_id)
            imported_id = result_id
        elif args.kind == "decompilation-plan":
            imported = 0
            for task in row.get("tasks") or []:
                task_id = task["taskId"]
                conn.execute(
                    """
                    INSERT INTO decompilation_tasks (
                      id, project_id, artifact_id, artifact_path, platform,
                      artifact_type, status, blocker_type, data_json,
                      created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      artifact_id=excluded.artifact_id,
                      artifact_path=excluded.artifact_path,
                      platform=excluded.platform,
                      artifact_type=excluded.artifact_type,
                      status=excluded.status,
                      blocker_type=excluded.blocker_type,
                      data_json=excluded.data_json,
                      updated_at=excluded.updated_at
                    """,
                    (
                        task_id,
                        args.project_id,
                        task.get("artifactId", ""),
                        task.get("artifactPath", ""),
                        task.get("platform", "unknown"),
                        task.get("artifactType", "unknown"),
                        task.get("status", "planned"),
                        task.get("blockerType", "none"),
                        json.dumps(task, ensure_ascii=False, sort_keys=True),
                        now(),
                        now(),
                    ),
                )
                write_event(conn, args.project_id, "decompilation_task.imported", f"imported decompilation task {task_id}", object_type="decompilation_task", object_id=task_id)
                imported += 1
            imported_id = f"decompilation-plan:{imported}"
        elif args.kind == "report-model":
            version = conn.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 AS version FROM report_models WHERE project_id = ?",
                (args.project_id,),
            ).fetchone()["version"]
            model_id = f"report-model-{version}"
            conn.execute(
                """
                INSERT INTO report_models (
                  id, project_id, version, data_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    model_id,
                    args.project_id,
                    version,
                    json.dumps(row, ensure_ascii=False, sort_keys=True),
                    now(),
                ),
            )
            write_event(conn, args.project_id, "report_model.imported", f"imported report model version {version}", object_type="report_model", object_id=model_id)
            imported_id = model_id
        else:
            raise ValueError(f"unsupported kind: {args.kind}")
        conn.commit()
    print(json.dumps({"ok": True, "kind": args.kind, "id": imported_id}, ensure_ascii=False))
    return 0


def cmd_register_worker(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    with connect(db_path) as conn:
        init_db(conn)
        ts = now()
        conn.execute(
            """
            INSERT INTO workers (
              id, project_id, worker_type, status, last_heartbeat_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              project_id=excluded.project_id,
              worker_type=excluded.worker_type,
              status=excluded.status,
              last_heartbeat_at=excluded.last_heartbeat_at
            """,
            (
                args.worker_id,
                args.project_id,
                args.worker_type,
                "idle",
                ts,
                ts,
            ),
        )
        write_event(conn, args.project_id, "worker.registered", f"registered worker {args.worker_id}", object_type="worker", object_id=args.worker_id)
        conn.commit()
    print(json.dumps({"ok": True, "workerId": args.worker_id}, ensure_ascii=False))
    return 0


def cmd_worker_heartbeat(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    with connect(db_path) as conn:
        init_db(conn)
        row = conn.execute("SELECT project_id FROM workers WHERE id = ?", (args.worker_id,)).fetchone()
        if row is None:
            print(json.dumps({"ok": False, "error": "worker not registered", "workerId": args.worker_id}, ensure_ascii=False))
            return 2
        ts = now()
        conn.execute(
            "UPDATE workers SET last_heartbeat_at = ?, status = CASE WHEN status = 'stopped' THEN status ELSE 'running' END WHERE id = ?",
            (ts, args.worker_id),
        )
        write_event(conn, row["project_id"], "worker.heartbeat", f"worker heartbeat {args.worker_id}", object_type="worker", object_id=args.worker_id)
        conn.commit()
    print(json.dumps({"ok": True, "workerId": args.worker_id, "heartbeatAt": ts}, ensure_ascii=False))
    return 0


def cmd_add_intent(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    input_data = json.loads(args.input_json) if args.input_json else {}
    with connect(db_path) as conn:
        init_db(conn)
        ts = now()
        conn.execute(
            """
            INSERT INTO intents (
              id, project_id, intent_type, status, priority, description,
              input_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              intent_type=excluded.intent_type,
              priority=excluded.priority,
              description=excluded.description,
              input_json=excluded.input_json,
              updated_at=excluded.updated_at
            """,
            (
                args.intent_id,
                args.project_id,
                args.intent_type,
                "pending",
                args.priority,
                args.description,
                json.dumps(input_data, ensure_ascii=False, sort_keys=True),
                ts,
                ts,
            ),
        )
        write_event(conn, args.project_id, "intent.added", f"added intent {args.intent_id}", object_type="intent", object_id=args.intent_id, payload=input_data)
        conn.commit()
    print(json.dumps({"ok": True, "intentId": args.intent_id}, ensure_ascii=False))
    return 0


def cmd_claim_intent(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    with connect(db_path) as conn:
        init_db(conn)
        worker = conn.execute("SELECT * FROM workers WHERE id = ?", (args.worker_id,)).fetchone()
        if worker is None:
            print(json.dumps({"ok": False, "error": "worker not registered", "workerId": args.worker_id}, ensure_ascii=False))
            return 2
        filters = ["project_id = ?", "status = 'pending'"]
        params: list[Any] = [args.project_id]
        if args.intent_type:
            filters.append("intent_type = ?")
            params.append(args.intent_type)
        where = " AND ".join(filters)
        row = conn.execute(
            f"""
            SELECT * FROM intents
            WHERE {where}
            ORDER BY
              CASE priority
                WHEN 'P0' THEN 0
                WHEN 'P1' THEN 1
                WHEN 'P2' THEN 2
                ELSE 3
              END,
              created_at
            LIMIT 1
            """,
            params,
        ).fetchone()
        if row is None:
            print(json.dumps({"ok": True, "claimed": False}, ensure_ascii=False))
            return 0
        ts = now()
        conn.execute(
            """
            UPDATE intents
            SET status = 'claimed', claimed_by = ?, claimed_at = ?, updated_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (args.worker_id, ts, ts, row["id"]),
        )
        conn.execute("UPDATE workers SET status = 'running', last_heartbeat_at = ? WHERE id = ?", (ts, args.worker_id))
        write_event(conn, args.project_id, "intent.claimed", f"claimed intent {row['id']}", object_type="intent", object_id=row["id"], payload={"workerId": args.worker_id})
        conn.commit()
        item = dict(row)
        item["input"] = json.loads(item.pop("input_json") or "{}")
        item["status"] = "claimed"
        item["claimed_by"] = args.worker_id
        item["claimed_at"] = ts
    print(json.dumps({"ok": True, "claimed": True, "intent": item}, ensure_ascii=False))
    return 0


def cmd_finish_intent(args: argparse.Namespace) -> int:
    db_path = Path(args.audit_dir) / "state.sqlite"
    payload = json.loads(args.payload) if args.payload else {}
    with connect(db_path) as conn:
        init_db(conn)
        row = conn.execute("SELECT * FROM intents WHERE id = ?", (args.intent_id,)).fetchone()
        if row is None:
            print(json.dumps({"ok": False, "error": "intent not found", "intentId": args.intent_id}, ensure_ascii=False))
            return 2
        if row["claimed_by"] not in (None, args.worker_id):
            print(json.dumps({"ok": False, "error": "intent claimed by another worker", "claimedBy": row["claimed_by"]}, ensure_ascii=False))
            return 3
        ts = now()
        conn.execute(
            """
            UPDATE intents
            SET status = ?, completed_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (args.status, ts if args.status in ("completed", "failed", "cancelled") else None, ts, args.intent_id),
        )
        conn.execute("UPDATE workers SET status = 'idle', last_heartbeat_at = ? WHERE id = ?", (ts, args.worker_id))
        write_event(conn, row["project_id"], f"intent.{args.status}", args.message or f"intent {args.status}", severity=args.severity, object_type="intent", object_id=args.intent_id, payload=payload)
        conn.commit()
    print(json.dumps({"ok": True, "intentId": args.intent_id, "status": args.status}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage code-security-audit SQLite state")
    parser.add_argument("--audit-dir", default="audit-v2")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize state database and project")
    init.add_argument("--project-id", default="proj-default")
    init.add_argument("--project-root", default=".")
    init.add_argument("--audit-mode", choices=["redteam", "full"], default="full")
    init.add_argument("--source-shape", choices=["source-only", "compiled-only", "mixed"], default="source-only")
    init.set_defaults(func=cmd_init)

    status = sub.add_parser("status", help="print state summary")
    status.set_defaults(func=cmd_status)

    add_event = sub.add_parser("add-event", help="append an event")
    add_event.add_argument("--project-id", required=True)
    add_event.add_argument("--event-type", required=True)
    add_event.add_argument("--message", required=True)
    add_event.add_argument("--severity", choices=["info", "warning", "error", "blocker"], default="info")
    add_event.add_argument("--object-type")
    add_event.add_argument("--object-id")
    add_event.add_argument("--payload")
    add_event.set_defaults(func=cmd_add_event)

    export = sub.add_parser("export-events", help="export events as JSONL")
    export.add_argument("--output")
    export.set_defaults(func=cmd_export_events)

    import_jsonl = sub.add_parser("import-jsonl", help="import structured JSONL fragments")
    import_jsonl.add_argument("--project-id", required=True)
    import_jsonl.add_argument("--kind", choices=[
        "findings",
        "callchains",
        "requests",
        "evidence",
        "capabilities",
        "mutations",
        "validation-tasks",
        "attack-chains",
    ], required=True)
    import_jsonl.add_argument("--file", required=True)
    import_jsonl.set_defaults(func=cmd_import_jsonl)

    import_json = sub.add_parser("import-json", help="import structured JSON document")
    import_json.add_argument("--project-id", required=True)
    import_json.add_argument("--kind", choices=["quality-result", "report-model", "decompilation-plan"], required=True)
    import_json.add_argument("--file", required=True)
    import_json.set_defaults(func=cmd_import_json)

    register_worker = sub.add_parser("register-worker", help="register or refresh a worker")
    register_worker.add_argument("--project-id", required=True)
    register_worker.add_argument("--worker-id", required=True)
    register_worker.add_argument("--worker-type", choices=["recon", "audit", "validate", "chain", "report", "reviewer"], required=True)
    register_worker.set_defaults(func=cmd_register_worker)

    heartbeat = sub.add_parser("worker-heartbeat", help="record a worker heartbeat")
    heartbeat.add_argument("--worker-id", required=True)
    heartbeat.set_defaults(func=cmd_worker_heartbeat)

    add_intent = sub.add_parser("add-intent", help="enqueue a worker intent")
    add_intent.add_argument("--project-id", required=True)
    add_intent.add_argument("--intent-id", required=True)
    add_intent.add_argument("--intent-type", choices=["recon", "audit", "validate", "chain", "report", "review"], required=True)
    add_intent.add_argument("--priority", choices=["P0", "P1", "P2", "P3"], default="P2")
    add_intent.add_argument("--description", required=True)
    add_intent.add_argument("--input-json")
    add_intent.set_defaults(func=cmd_add_intent)

    claim_intent = sub.add_parser("claim-intent", help="claim the next pending intent")
    claim_intent.add_argument("--project-id", required=True)
    claim_intent.add_argument("--worker-id", required=True)
    claim_intent.add_argument("--intent-type", choices=["recon", "audit", "validate", "chain", "report", "review"])
    claim_intent.set_defaults(func=cmd_claim_intent)

    finish_intent = sub.add_parser("finish-intent", help="complete, block, fail, or cancel an intent")
    finish_intent.add_argument("--worker-id", required=True)
    finish_intent.add_argument("--intent-id", required=True)
    finish_intent.add_argument("--status", choices=["completed", "blocked", "failed", "cancelled"], required=True)
    finish_intent.add_argument("--severity", choices=["info", "warning", "error", "blocker"], default="info")
    finish_intent.add_argument("--message")
    finish_intent.add_argument("--payload")
    finish_intent.set_defaults(func=cmd_finish_intent)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
