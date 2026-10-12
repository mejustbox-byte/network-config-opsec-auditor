# Check matrix

| ID | Pass | Fail | Unknown/inapplicable |
|---|---|---|---|
| NET-001 | Management sources fully inside trusted union | Any management source outside trusted union | Missing source/management annotation; non-management inapplicable |
| NET-002 | No same-family source/destination /0 pair with all ports | Matching-family /0 pair and any ports | Missing networks/ports or unknown protocol |
| NET-003 | Declared protected management service | Declared unprotected service | Unknown service/management; non-management inapplicable |
| NET-004 | Significant rule logging true | Significant rule logging false | Missing significance/logging; non-significant inapplicable |

Fail severities are critical/high/high/medium respectively. NET-002 applies to tcp, udp and any, and requires common address family. A pass for one narrow heuristic does not establish adequate segmentation. Disabled or denied rules are inapplicable to all four checks; unknown activation/action leaves all four not_tested.

[Index](index.md) · [Other language](../ru/check-matrix.md)

Wildcard coverage is computed after collapsing adjacent and overlapping CIDRs within each address family. Two /1 ranges covering all IPv4 addresses are therefore equivalent to /0 for NET-002.
