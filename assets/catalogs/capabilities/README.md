# Capability Catalog

Capabilities are reusable, confirmed attacker abilities that can supply another finding's preconditions.

## Core Rule

Only confirmed capabilities may supply confirmed findings. Hypothesis capabilities may only produce hypothesis chains.

## Initial Vocabulary

| Capability | Meaning |
|---|---|
| `obtain-operator-id` | Retrieve an operator/user identifier usable by other requests |
| `obtain-session` | Create or obtain a valid session |
| `populate-user-object` | Populate server-side user context such as `m:userObject` |
| `read-db-row` | Read selected database rows |
| `write-db-row` | Insert or update database rows under L2 controls |
| `read-file` | Read server-side file content |
| `write-file` | Write a server-side file under L2 controls |
| `ssrf-request` | Make the server issue a controlled request |

## EMS Regression

- `vul-127` requires `write-db-row` from `vul-001`.
- `vul-131` requires `obtain-operator-id`, `obtain-session`, and `populate-user-object`.

## Constraints

- Capability graph must be acyclic.
- Default maximum chain depth is 3.
- Capability evidence must be traceable to requests and assertions.
