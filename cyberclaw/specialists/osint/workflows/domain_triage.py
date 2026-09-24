"""Domain Triage workflow orchestrating domain metadata, DNS, and TLS certificates."""

from __future__ import annotations

from typing import Any, Callable, Dict, List
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
)
from cyberclaw.specialists.osint.workflows.base import OSINTWorkflow
from cyberclaw.types import Relationship


class DomainTriageWorkflow(OSINTWorkflow):
    """Repeatable workflow performing initial passive OSINT triage on a domain target:

    Step 1: Domain metadata lookup (registrar, status, nameservers)
    Step 2: DNS records lookup (A, MX, NS)
    Step 3: Certificate metadata lookup (SANs, validity)
    Step 4: Correlate discovered entities into relationships
    """

    def __init__(self) -> None:
        super().__init__(
            id="osint.workflow:domain_triage",
            name="Domain Passive Triage Workflow",
            description="Comprehensive passive domain triage combining registrar, DNS, and TLS certificates.",
        )

    def execute(
        self,
        parameters: Dict[str, Any],
        context: ExecutionContext,
        capability_invoker: Callable[[str, Dict[str, Any], ExecutionContext], ExecutionResult],
    ) -> ExecutionResult:
        target = parameters.get("target")
        if not target:
            return ExecutionResult.failure(
                error="Target parameter is required for DomainTriageWorkflow",
                error_code="MISSING_TARGET",
                execution_id=context.execution_id,
            )

        all_evidence: List[Evidence] = []
        relationships: List[Relationship] = []
        step_outputs: Dict[str, Any] = {}

        # 1. Domain Metadata
        meta_res = capability_invoker(CAPABILITY_DOMAIN_METADATA, {"target": target}, context)
        if meta_res.completed_normally and meta_res.evidence:
            all_evidence.extend(meta_res.evidence)
            step_outputs["domain_metadata"] = meta_res.output

        # 2. DNS Lookup
        dns_res = capability_invoker(CAPABILITY_DNS_LOOKUP, {"target": target}, context)
        if dns_res.completed_normally and dns_res.evidence:
            all_evidence.extend(dns_res.evidence)
            step_outputs["dns"] = dns_res.output

        # 3. Certificate Metadata
        cert_res = capability_invoker(CAPABILITY_CERT_METADATA, {"target": target}, context)
        if cert_res.completed_normally and cert_res.evidence:
            all_evidence.extend(cert_res.evidence)
            step_outputs["certificate"] = cert_res.output

        # 4. Correlation / Relationship extraction
        # Extract IPs and Nameservers to link to the domain
        if dns_res.output and isinstance(dns_res.output, dict):
            records = dns_res.output.get("records", {})
            for ip in records.get("A", []):
                relationships.append(
                    Relationship(
                        source_id=target,
                        target_id=ip,
                        relation_type="resolves_to_ip",
                        confidence=0.98,
                    )
                )
            for ns in records.get("NS", []):
                relationships.append(
                    Relationship(
                        source_id=target,
                        target_id=ns,
                        relation_type="delegated_to_nameserver",
                        confidence=0.95,
                    )
                )

        if not all_evidence:
            return ExecutionResult.success_empty(
                output={"workflow": self.id, "target": target, "steps": step_outputs},
                execution_id=context.execution_id,
            )

        return ExecutionResult.success(
            evidence=all_evidence,
            output={
                "workflow": self.id,
                "target": target,
                "relationships": [r.model_dump() for r in relationships],
                "steps": step_outputs,
            },
            execution_id=context.execution_id,
            metadata={"relationships_count": len(relationships)},
        )
