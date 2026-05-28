# SQL Injection Payload Asset

This asset tracks SQL injection validation guidance for v2. It is sourced from legacy `scripts/tools/payload_templates/sqli_by_dialect.md` but is not a verbatim directory copy.

## Production Rules

- Prefer read-only proofs for L1 validation.
- L2 writes are allowed only with mutation evidence: baseline, mutation, proof, cleanup, post-cleanup assert.
- Do not auto-redact internal evidence.
- Every SQL payload embedded in a report must appear in a complete raw HTTP request or executable script.
- Ellipsis (`...`) in SQL payloads is a blocker.

## EMS Regression Coverage

- `vul-001`: SQL gateway proof and capability extraction.
- `vul-126`: form-urlencoded request format variant.
- `vul-127`: second-order SQL via capability-provided DB write.
- `vul-131`: capability chain into authenticated SQL injection.

## Future Structured Form

The next production step is to convert dialect payloads into machine-readable records:

```json
{
  "dialect": "oracle",
  "context": "select-list",
  "safeLevel": "L1",
  "payload": "SELECT USER AS U FROM DUAL",
  "assertion": "response contains current DB user"
}
```
