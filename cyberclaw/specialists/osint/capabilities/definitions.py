"""OSINT capability definitions for OSINT Specialist v0.1.

Safe, deterministic, non-offensive intelligence capabilities suitable for
domain metadata, DNS records, certificate information, and WHOIS lookups.
"""

from __future__ import annotations

from typing import Dict, List
from cyberclaw.capabilities.capability import Capability

CAPABILITY_DOMAIN_METADATA = "osint.domain_metadata"
CAPABILITY_DNS_LOOKUP = "osint.dns_lookup"
CAPABILITY_CERT_METADATA = "osint.cert_metadata"
CAPABILITY_WHOIS_LOOKUP = "osint.whois_lookup"


def get_osint_capabilities() -> List[Capability]:
    """Return all capabilities provided by OSINT Specialist v0.1."""
    return [
        Capability(
            id=CAPABILITY_DOMAIN_METADATA,
            name="Domain Metadata Lookup",
            description="Passive lookup of domain status, registrar, and nameservers",
            category="osint",
            input_schema={
                "required": ["target"],
                "properties": {
                    "target": {"type": "string"},
                },
            },
            output_schema={
                "properties": {
                    "domain": {"type": "string"},
                    "registrar": {"type": "string"},
                    "status": {"type": "array"},
                    "nameservers": {"type": "array"},
                }
            },
            required_permissions=["network:read"],
        ),
        Capability(
            id=CAPABILITY_DNS_LOOKUP,
            name="DNS Records Lookup",
            description="Passive query of DNS resource records (A, AAAA, MX, TXT, NS)",
            category="osint",
            input_schema={
                "required": ["target"],
                "properties": {
                    "target": {"type": "string"},
                    "record_types": {"type": "array"},
                },
            },
            output_schema={
                "properties": {
                    "records": {"type": "object"},
                }
            },
            required_permissions=["network:read"],
        ),
        Capability(
            id=CAPABILITY_CERT_METADATA,
            name="Certificate Metadata Lookup",
            description="Passive extraction of public TLS/SSL certificate metadata and SANs",
            category="osint",
            input_schema={
                "required": ["target"],
                "properties": {
                    "target": {"type": "string"},
                    "port": {"type": "integer"},
                },
            },
            output_schema={
                "properties": {
                    "subject": {"type": "string"},
                    "issuer": {"type": "string"},
                    "sans": {"type": "array"},
                    "valid_until": {"type": "string"},
                }
            },
            required_permissions=["network:read"],
        ),
        Capability(
            id=CAPABILITY_WHOIS_LOOKUP,
            name="WHOIS Registration Lookup",
            description="Passive retrieval of public domain registration information",
            category="osint",
            input_schema={
                "required": ["target"],
                "properties": {
                    "target": {"type": "string"},
                },
            },
            output_schema={
                "properties": {
                    "registrant": {"type": "object"},
                    "dates": {"type": "object"},
                }
            },
            required_permissions=["network:read"],
        ),
    ]
