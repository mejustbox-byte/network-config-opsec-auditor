# ADR: offline inventory consumer

Accepted: Python 3.12+, ipaddress, JSON, unittest and exact report-contract 0.1.0a1. CIDR arithmetic needs no network access and shared report validation keeps statuses and coverage consistent with the other auditors. Bootstrap installs the released dependency wheel using its published SHA-256.

Build tooling pins setuptools 84.0.0 and wheel 0.48.0; CI uses Python 3.13 on Linux, Windows and macOS. Vendor SDKs and first-match firewall simulators are excluded until actual export semantics are inspected and independently tested. Input URLs and dynamic plugins are not supported. Initial installation needs network; assessment does not.

[Index](index.md) · [Other language](../ru/adr.md)
