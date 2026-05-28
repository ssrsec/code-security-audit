PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', 'state/v1');

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  root_path TEXT NOT NULL,
  audit_mode TEXT NOT NULL CHECK (audit_mode IN ('redteam', 'full')),
  source_shape TEXT NOT NULL CHECK (source_shape IN ('source-only', 'compiled-only', 'mixed')),
  status TEXT NOT NULL CHECK (status IN ('initialized', 'recon', 'audit_planning', 'auditing', 'coverage_gate', 'validation_planning', 'validating', 'validation_gate', 'attack_graph', 'report_model', 'render', 'completed', 'supplemental_validation', 'patch_report', 'paused', 'blocked_live_target', 'blocked_user_input', 'blocked_tooling', 'blocked_decompile', 'blocked_environment')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'error', 'blocker')),
  object_type TEXT,
  object_id TEXT,
  message TEXT NOT NULL,
  payload_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workers (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  worker_type TEXT NOT NULL CHECK (worker_type IN ('recon', 'audit', 'validate', 'chain', 'report', 'reviewer')),
  status TEXT NOT NULL CHECK (status IN ('idle', 'running', 'failed', 'stopped')),
  last_heartbeat_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intents (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  intent_type TEXT NOT NULL CHECK (intent_type IN ('recon', 'audit', 'validate', 'chain', 'report', 'review')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'completed', 'blocked', 'failed', 'cancelled')),
  priority TEXT NOT NULL DEFAULT 'P2' CHECK (priority IN ('P0', 'P1', 'P2', 'P3')),
  description TEXT NOT NULL,
  input_json TEXT,
  claimed_by TEXT REFERENCES workers(id) ON DELETE SET NULL,
  claimed_at TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('candidate', 'challenged', 'confirmed', 'hypothesis', 'rejected', 'deferred', 'reported', 'patched')),
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  validation_level TEXT NOT NULL CHECK (validation_level IN ('V0', 'V1', 'V2', 'V3', 'V4')),
  auth_level TEXT NOT NULL CHECK (auth_level IN ('none', 'low-privileged', 'admin', 'unknown')),
  title TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_sources (
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL,
  PRIMARY KEY (finding_id, source_id)
);

CREATE TABLE IF NOT EXISTS callchains (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  auth_usage TEXT NOT NULL CHECK (auth_usage IN ('none', 'cookie', 'bearer', 'basic', 'custom')),
  raw TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  request_id TEXT REFERENCES requests(id) ON DELETE SET NULL,
  environment TEXT NOT NULL CHECK (environment IN ('live-target', 'local', 'unit', 'mock', 'static')),
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  provider_finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  confidence TEXT NOT NULL CHECK (confidence IN ('confirmed', 'hypothesis')),
  operation_class TEXT NOT NULL CHECK (operation_class IN ('read-only', 'write-capable', 'state-changing', 'destructive', 'unknown')),
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS capability_edges (
  provider_capability_id TEXT NOT NULL REFERENCES capabilities(id) ON DELETE CASCADE,
  consumer_finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (provider_capability_id, consumer_finding_id)
);

CREATE TABLE IF NOT EXISTS mutations (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  operation_level TEXT NOT NULL CHECK (operation_level IN ('L1', 'L2', 'L3')),
  mutation_type TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_tasks (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  priority TEXT NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'blocked', 'completed', 'failed', 'skipped')),
  safe_level TEXT NOT NULL CHECK (safe_level IN ('L1', 'L2', 'L3')),
  blocker_type TEXT NOT NULL DEFAULT 'none',
  next_action TEXT NOT NULL,
  claimed_by TEXT REFERENCES workers(id) ON DELETE SET NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decompilation_tasks (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  artifact_id TEXT NOT NULL,
  artifact_path TEXT NOT NULL,
  platform TEXT NOT NULL,
  artifact_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('planned', 'running', 'completed', 'failed', 'blocked')),
  blocker_type TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_chains (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('confirmed', 'hypothesis')),
  chain_type TEXT NOT NULL CHECK (chain_type IN ('finding-chain', 'capability-chain', 'mixed')),
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quality_results (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  gate TEXT NOT NULL CHECK (gate IN ('schema', 'semantic', 'poc', 'render', 'regression', 'all')),
  exit_code INTEGER NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS report_models (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_intents_project_status ON intents(project_id, status, priority);
CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_id, status);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_capabilities_project ON capabilities(project_id, confidence);
CREATE INDEX IF NOT EXISTS idx_validation_tasks_status ON validation_tasks(status, priority);
CREATE INDEX IF NOT EXISTS idx_decompilation_tasks_status ON decompilation_tasks(project_id, status);
