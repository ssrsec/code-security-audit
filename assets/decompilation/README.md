# Decompilation Assets

This directory tracks decompilation playbooks and tool references for projects that are `compiled-only` or `mixed`.

Rules:

- Recon must record compiled artifacts before audit workers infer source coverage.
- Decompilation output is derived evidence, not the original source of truth.
- Tool choice must be explicit and OS-aware.
- If decompilation fails, the audit state must become `blocked_decompile` or record an explicit limitation.
