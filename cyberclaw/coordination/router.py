"""Capability-based routing of Information Requirements to eligible Specialists."""

from __future__ import annotations

from typing import List, Optional, Tuple
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.coordination.requirements import InformationRequirement
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistHealth
from cyberclaw.specialists.registry import SpecialistRegistry


class RequirementRouter:
    """Deterministically resolves Information Requirements to healthy, authorized Specialists."""

    def __init__(
        self,
        specialist_registry: SpecialistRegistry,
        capability_registry: CapabilityRegistry,
    ) -> None:
        self.specialists = specialist_registry
        self.capabilities = capability_registry

    def resolve_specialist(
        self,
        requirement: InformationRequirement,
    ) -> Tuple[Optional[Specialist], Optional[str], Optional[str]]:
        """Resolve which Specialist and Capability should fulfill the requirement.

        Returns (specialist, capability_id, failure_reason).
        """
        all_specialists = self.specialists.list_specialists()
        if not all_specialists:
            return None, None, "No specialists registered in Core."

        # Filter healthy specialists only
        healthy_specialists = [
            s for s in all_specialists if s.get_health() == SpecialistHealth.HEALTHY
        ]
        if not healthy_specialists:
            return None, None, "No healthy specialists available."

        # Case 1: Requirement explicitly requests a specific capability
        if requirement.assigned_capability_id:
            cap_id = requirement.assigned_capability_id
            for s in healthy_specialists:
                if cap_id in s.capabilities:
                    return s, cap_id, None
            return None, None, f"No healthy specialist provides explicit capability '{cap_id}'"

        # Case 2: Resolve based on evidence_types_sought
        sought = [t.lower() for t in requirement.evidence_types_sought]
        best_match: Optional[Tuple[Specialist, str, int]] = None

        for specialist in healthy_specialists:
            for cap_id in specialist.capabilities:
                cap_lower = cap_id.lower()
                cap_obj = self.capabilities.get_capability(cap_id)
                cap_desc = (cap_obj.description if cap_obj else "").lower()

                match_score = 0
                for need in sought:
                    if need in cap_lower:
                        match_score += 10
                    elif need in cap_desc:
                        match_score += 5
                    # Check substring e.g. "dns" in "osint.dns_lookup"
                    tokens = need.replace(".", "_").split("_")
                    for tok in tokens:
                        if tok and tok in cap_lower:
                            match_score += 2

                if match_score > 0:
                    if best_match is None or match_score > best_match[2]:
                        best_match = (specialist, cap_id, match_score)

        if best_match:
            return best_match[0], best_match[1], None

        return (
            None,
            None,
            f"No specialist capability matched information requirement '{requirement.description}' for needs {requirement.evidence_types_sought}",
        )
