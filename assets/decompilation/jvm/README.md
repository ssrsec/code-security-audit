# JVM Decompilation Playbook

Use for `.jar`, `.war`, `.ear`, and `.class` artifacts.

## Expected Flow

1. Record the compiled artifact in `project.json.compiledArtifacts`.
2. Create a decompilation task before sink/control audit.
3. Preserve the original artifact path and hash when available.
4. Run the configured JVM decompiler wrapper.
5. Store decompiled output as derived workspace material.
6. Mark limitations for failed classes, obfuscation, missing dependencies, or partial archives.

## Tooling Notes

The legacy project references decompiler tooling under `scripts/tools/decompilers/`. v2 should keep tool wrappers OS-aware and avoid assuming one platform-specific binary.
