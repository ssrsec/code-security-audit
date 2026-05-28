# Attack Chain Catalog

v2 unifies legacy vulnerability combinations and primitive chains into one attack graph model.

## Chain Requirements

Every chain must include:

- At least two nodes.
- A concrete transfer edge between nodes.
- Evidence or capability references.
- A value increase.

## Value Increase

Accepted value increases:

- `reduces-preconditions`
- `increases-impact`
- `improves-reliability`
- `bypasses-network`
- `bypasses-auth`
- `enables-followup`

Combined severity does not need to numerically exceed the highest individual severity. A chain is valuable if it lowers preconditions, improves reliability, or unlocks a new capability.

## EMS Regression

- `vul-127`: SQL write capability enables second-order SQL injection.
- `vul-131`: operator ID + session + user object enables authenticated SQL injection.
