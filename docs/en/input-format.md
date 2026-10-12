# Selected export: neutral-json-v1

The root has exactly schema_version, scope, synthetic, semantics, trusted_sources and rules. Schema is network-inventory-1.0 and semantics must be rule-inventory. Scope is a nonempty string up to 128 characters; synthetic is a strict boolean. trusted_sources is a nonempty list of canonical IPv4/IPv6 CIDRs.

Each rule has exactly id, enabled, action, sources, destinations, protocol, ports, management, management_service, significant and logging. IDs are unique strings up to 128 characters. Flags are true/false/null; actions allow/deny/unknown; protocols tcp/udp/any/unknown. Sources/destinations are nonempty CIDR lists or null. Ports are unique integers 1–65535, the string any, or null. Service is a string up to 40 characters or null. Host-bit CIDRs, duplicate networks, unknown fields and unsupported schema/semantics are rejected.

[Index](index.md) · [Other language](../ru/input-format.md)
