"""Optional live OSINT provider.

Disabled unless constructed with enabled=True. Tests must not enable it.
A network failure is a provider failure, never an empty observation.
Lookups are passive and the target is validated before any socket call.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Any, Dict, Optional, Tuple
from urllib.error import URLError
from urllib.request import urlopen

from cyberclaw.authority.dispatch import governed_dispatch
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_WHOIS_LOOKUP,
)
from cyberclaw.specialists.osint.normalizers.normalizer import OSINTNormalizer
from cyberclaw.specialists.osint.providers.base import OSINTProvider
from cyberclaw.specialists.osint.providers.fixtures import PROVIDER_VERSION


_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class LiveOSINTProvider(OSINTProvider):
    """Passive DNS, TLS, or RDAP lookup. Off unless explicitly enabled."""

    def __init__(
        self,
        capability_id: str,
        enabled: bool = False,
        rdap_base_url: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        super().__init__(
            id=f"live.osint.{capability_id}",
            name=f"Live OSINT provider for {capability_id}",
            capability_id=capability_id,
            priority=50,
            metadata={"version": PROVIDER_VERSION, "mode": "live", "enabled": enabled},
        )
        self.enabled = enabled
        self.rdap_base_url = rdap_base_url
        self.timeout_seconds = timeout_seconds
        self.calls = 0
        self.network_attempts = 0
        self.version = PROVIDER_VERSION

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        if not self.enabled:
            return False, "Live OSINT provider is disabled. Pass enabled=True to allow a network lookup."
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        if governed_dispatch(context) is None:
            return ExecutionResult.failure(
                error="Live OSINT provider refused an ungoverned invocation.",
                error_code="UNGOVERNED_PROVIDER_INVOCATION",
                execution_id=context.execution_id,
            )
        if not self.enabled:
            return ExecutionResult.failure(
                error="Live OSINT provider is disabled. A disabled provider is not an empty observation.",
                error_code="LIVE_PROVIDER_DISABLED",
                execution_id=context.execution_id,
            )

        target = str(parameters.get("target") or "").strip().lower()
        if not _DOMAIN.match(target):
            return ExecutionResult.failure(
                error="Live OSINT provider rejected a target that is not a bare domain.",
                error_code="VALIDATION_FAILURE",
                execution_id=context.execution_id,
            )

        self.calls += 1
        self.network_attempts += 1
        try:
            payload, source_reference = self._collect(target)
        except (socket.gaierror, socket.timeout, TimeoutError, URLError, ssl.SSLError, OSError) as exc:
            return ExecutionResult.failure(
                error=f"Live OSINT lookup failed: {type(exc).__name__}",
                error_code="LIVE_LOOKUP_FAILED",
                execution_id=context.execution_id,
            )

        if payload is None:
            return ExecutionResult.success_empty(
                output={"target": target, "provider_version": self.version},
                execution_id=context.execution_id,
            )

        evidence = OSINTNormalizer.normalize(
            capability_id=self.capability_id,
            raw_data=payload,
            target=target,
            provider_id=self.id,
            context=context,
            provider_version=self.version,
            source_reference=source_reference,
            collected_at=None,
        )
        if not evidence:
            return ExecutionResult.success_empty(
                output={"target": target, "provider_version": self.version},
                execution_id=context.execution_id,
            )
        return ExecutionResult.success(
            evidence=evidence,
            output={"target": target, "provider_version": self.version},
            execution_id=context.execution_id,
        )

    def _collect(self, target: str) -> Tuple[Optional[Dict[str, Any]], str]:
        if self.capability_id == CAPABILITY_DNS_LOOKUP:
            addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
                }
            )
            if not addresses:
                return None, "stdlib:socket.getaddrinfo"
            return {"records": {"A": addresses}}, "stdlib:socket.getaddrinfo"
        if self.capability_id == CAPABILITY_CERT_METADATA:
            pem = ssl.get_server_certificate((target, 443), timeout=self.timeout_seconds)
            return {
                "subject": target,
                "issuer": None,
                "sans": [target],
                "serial_number": None,
                "pem_present": bool(pem),
            }, "stdlib:ssl.get_server_certificate"
        if self.capability_id == CAPABILITY_WHOIS_LOOKUP:
            if not self.rdap_base_url:
                raise OSError("RDAP base URL was not configured")
            url = self.rdap_base_url.rstrip("/") + "/" + target
            if not url.startswith("https://"):
                raise OSError("RDAP base URL must be https")
            with urlopen(url, timeout=self.timeout_seconds) as response:
                raw = response.read(65536)
            return {"raw_whois": raw.decode("utf-8", errors="replace")}, url
        raise OSError(f"No live collector for {self.capability_id}")
