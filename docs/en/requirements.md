# Scope and acceptance

This alpha checks an exported inventory of network rules in one explicitly selected format: neutral-json-v1. It supplies four inventory checks and an opsec-1.0 report. It does not scan networks, connect to devices, alter configuration or establish effective reachability.

Acceptance includes positive, negative, unknown and malformed inputs for the implemented controls, IPv4/IPv6 handling, trusted-CIDR unions, resource limits and CLI behavior. Unknown action, service or rule annotations remain not_tested. Denied and disabled rules are not_applicable. All public examples are synthetic.

[Index](index.md) · [Other language](../ru/requirements.md)
