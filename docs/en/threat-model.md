# Threat model and limits

Untrusted input may contain malformed CIDRs, misleading annotations or private network identifiers. Exact fields, strict types, JSON byte/depth limits, unique IDs, port bounds and exclusive output reduce common errors. No input commands or network endpoints are executed. Errors do not echo source content.

Residual risks include dishonest exports, overlapping rules, filesystem races, runtime/dependency bugs and bounded CPU/RAM use. Rule order, shadowing, NAT, statefulness, zones, routing, inherited policies and effective reachability are not evaluated. IDs and scope are not anonymized. No producer authentication or automatic sanitization is supplied, and report validity does not authorize publication.

[Index](index.md) · [Other language](../ru/threat-model.md)
