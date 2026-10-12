# Management service classification

Unprotected service labels: telnet, http, snmpv1, snmpv2c and ftp. Protected labels: ssh, https, snmpv3 and winrm-https. Any other label, including a vendor-specific management protocol, remains not_tested. Labels are case-sensitive and are supplied by the export producer.

The alpha does not inspect protocol negotiation, cipher strength, authentication, certificates or actual port/service bindings. Even a protected label can describe a misconfigured service. management and significant are explicit producer annotations; false labels can hide relevant checks. Review the mapping before normalizing a vendor export.

[Index](index.md) · [Other language](../ru/service-semantics.md)
