# Выбранный экспорт: neutral-json-v1

Корень содержит ровно schema_version, scope, synthetic, semantics, trusted_sources и rules. Schema — network-inventory-1.0, semantics — только rule-inventory. Scope — непустая строка до 128 символов; synthetic — строго boolean. trusted_sources — непустой список канонических IPv4/IPv6 CIDR.

Правило содержит ровно id, enabled, action, sources, destinations, protocol, ports, management, management_service, significant и logging. ID уникальны и не длиннее 128 символов. Флаги true/false/null; actions allow/deny/unknown; protocols tcp/udp/any/unknown. Sources/destinations — непустые CIDR-списки либо null. Ports — уникальные целые 1–65535, строка any либо null. Service — строка до 40 символов либо null. CIDR с host bits, повторные сети, лишние поля и другие schema/semantics отвергаются.

[Index](index.md) · [Other language](../en/input-format.md)
