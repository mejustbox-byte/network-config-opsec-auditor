# Architecture

CLI → strict bounded JSON loader → exact inventory model → CIDR checks and annotations → normalized report → exclusive new output. The released opsec-report-contract 0.1.0a1 supplies strict parsing, report validation and coverage semantics. Python ipaddress handles canonical networks without DNS.

Input is bounded to 8 MiB and depth 64. Up to 1000 rules, 128 source/destination CIDRs per rule and 256 numeric ports are supported. --max-rules lowers the rule limit. Each rule produces NET-001 through NET-004 with unique identities. Reports do not copy raw CIDRs or service values, but scope/rule IDs remain user identifiers and need privacy review.

[Index](index.md) · [Other language](../ru/architecture.md)
