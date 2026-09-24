"""Minimal Network Specialist mock for multi-specialist coordination verification."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source
from cyberclaw.workspace.layout import WorkspaceLayout


class NetworkSpecialist(SpecialistEndpoint):
    """Minimal autonomous Network Specialist subsystem for testing multi-specialist coordination."""

    SPECIALIST_ID = "network_specialist"
    SPECIALIST_NAME = "CyberClaw Network Specialist"
    VERSION = "0.1.0"

    CAPABILITY_PORT_SCAN = "network.port_scan"
    CAPABILITY_SERVICE_PROBE = "network.service_probe"

    def __init__(self, workspace_base: Optional[Path] = None) -> None:
        self.workspace_base = (workspace_base or Path("./workspace/specialists/network")).resolve()
        self.layout = WorkspaceLayout(self.workspace_base)
        self.layout.ensure_directories()
        self._health = SpecialistHealth.HEALTHY

    def health(self) -> SpecialistHealth:
        return self._health

    def set_health(self, health: SpecialistHealth) -> None:
        self._health = health

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        target_ip = request.parameters.get("target_ip") or request.parameters.get("target", "127.0.0.1")

        if request.parameters.get("simulate_failure"):
            res = ExecutionResult.failure(
                error=f"Network scan failed on '{target_ip}': Host unreachable or firewalled",
                error_code="NETWORK_UNREACHABLE",
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(self.SPECIALIST_ID, request.request_id, res)

        if request.parameters.get("simulate_empty"):
            res = ExecutionResult.success_empty(
                output={"target_ip": target_ip, "open_ports": []},
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(self.SPECIALIST_ID, request.request_id, res)

        source = Source(type="network_probe", name="mock_network_scanner", reliability=0.95)
        prov = Provenance(
            execution_id=request.context.execution_id,
            investigation_id=request.investigation_id,
            specialist_id=self.SPECIALIST_ID,
            capability_id=request.capability_id,
            parameters={"target_ip": target_ip},
        )

        if request.capability_id == self.CAPABILITY_SERVICE_PROBE:
            ev = Evidence(
                type="network.service",
                subject=target_ip,
                value={
                    "ip": target_ip,
                    "service": "HTTPS",
                    "banner": "nginx/1.24.0",
                    "port": 443,
                },
                source=source,
                provenance=prov,
                confidence=0.95,
            )
            res = ExecutionResult.success(
                evidence=[ev],
                output={"service": "HTTPS", "port": 443},
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(self.SPECIALIST_ID, request.request_id, res)

        # Default: CAPABILITY_PORT_SCAN
        open_ports = [80, 443, 22]
        ev = Evidence(
            type="network.port_scan",
            subject=target_ip,
            value={"open_ports": open_ports, "target_ip": target_ip},
            source=source,
            provenance=prov,
            confidence=0.95,
        )
        res = ExecutionResult.success(
            evidence=[ev],
            output={"target_ip": target_ip, "open_ports": open_ports},
            execution_id=request.context.execution_id,
        )
        return SpecialistResponse.from_result(self.SPECIALIST_ID, request.request_id, res)

    def list_capabilities(self) -> List[str]:
        return [self.CAPABILITY_PORT_SCAN, self.CAPABILITY_SERVICE_PROBE]

    def as_specialist(self) -> Specialist:
        return Specialist(
            id=self.SPECIALIST_ID,
            name=self.SPECIALIST_NAME,
            version=self.VERSION,
            capabilities=self.list_capabilities(),
            endpoint=self,
            permissions=["network:read"],
            metadata={"description": "Autonomous network context subsystem"},
        )
