"""Deterministic Correlation Engine for CyberClaw Core.

Extracts entities, derives observed and inferred relationships, tracks provenance,
and flags evidence contradictions without modifying underlying raw facts.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from cyberclaw.correlation.models import ContradictionRecord
from cyberclaw.correlation.rules import (
    CertificateIdentityCorrelationRule,
    CorrelationRule,
    DnsResolutionCorrelationRule,
    NetworkServiceCorrelationRule,
    SharedInfrastructureCorrelationRule,
)
from cyberclaw.evidence.models import Evidence
from cyberclaw.types import Entity, Relationship


class CorrelationResult(BaseModel):
    """Aggregated output from a correlation execution run."""

    investigation_id: str
    new_entities: List[Entity] = Field(default_factory=list)
    new_relationships: List[Relationship] = Field(default_factory=list)
    contradictions: List[ContradictionRecord] = Field(default_factory=list)
    observed_count: int = 0
    inferred_count: int = 0


class CorrelationEngine:
    """Orchestrates deterministic evidence correlation rules."""

    def __init__(self, custom_rules: Optional[List[CorrelationRule]] = None) -> None:
        if custom_rules is not None:
            self.rules = list(custom_rules)
        else:
            self.rules = [
                DnsResolutionCorrelationRule(),
                CertificateIdentityCorrelationRule(),
                NetworkServiceCorrelationRule(),
                SharedInfrastructureCorrelationRule(),
            ]

    def register_rule(self, rule: CorrelationRule) -> None:
        self.rules.append(rule)

    def correlate(
        self,
        evidence_list: List[Evidence],
        existing_entities: Optional[Dict[str, Entity]] = None,
        investigation_id: str = "global",
    ) -> CorrelationResult:
        """Run all correlation rules over evidence to derive entities and relationships."""
        entities_dict: Dict[str, Entity] = dict(existing_entities or {})
        derived_relationships: List[Relationship] = []
        contradictions_found: List[ContradictionRecord] = []

        seen_rel_keys = set()

        for rule in self.rules:
            entities, rels, contras = rule.evaluate(evidence_list, entities_dict, investigation_id)

            for ent in entities:
                if ent.name not in entities_dict:
                    entities_dict[ent.name] = ent

            for rel in rels:
                key = (rel.source_id, rel.target_id, rel.relation_type, rel.is_inferred)
                if key not in seen_rel_keys:
                    seen_rel_keys.add(key)
                    derived_relationships.append(rel)

            contradictions_found.extend(contras)

        observed = sum(1 for r in derived_relationships if not r.is_inferred)
        inferred = sum(1 for r in derived_relationships if r.is_inferred)

        return CorrelationResult(
            investigation_id=investigation_id,
            new_entities=list(entities_dict.values()),
            new_relationships=derived_relationships,
            contradictions=contradictions_found,
            observed_count=observed,
            inferred_count=inferred,
        )
