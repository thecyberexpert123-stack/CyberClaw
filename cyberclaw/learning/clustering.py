"""Source-family grouping so copied workflows are not counted as independent samples."""

from __future__ import annotations

from typing import Dict, List, Sequence

from cyberclaw.learning.models import InvestigationExperience, SourceFamily, SourceFamilyClustering


class _UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def add(self, item: str) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: str, right: str) -> None:
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left == root_right:
            return
        if root_left < root_right:
            self.parent[root_right] = root_left
        else:
            self.parent[root_left] = root_right


class SourceFamilyGrouper:
    """Cluster experiences that share declared lineage or upstream sources.

    Integrates with knowledge provenance by honoring source ids already
    extracted via ``calculate_source_independence`` and evidence source identity.
    Shared upstream sources collapse otherwise separate investigation ids into
    one family so sample counts cannot be inflated by copied feeds or templates.
    """

    ALGORITHM = "source_lineage_union_find_v0.1"

    @classmethod
    def group(cls, experiences: Sequence[InvestigationExperience]) -> SourceFamilyClustering:
        uf = _UnionFind()
        source_to_experiences: Dict[str, List[str]] = {}
        for experience in experiences:
            uf.add(experience.experience_id)
            for source_id in experience.upstream_source_ids:
                source_to_experiences.setdefault(source_id, []).append(experience.experience_id)
            for root in experience.source_independence_roots:
                source_to_experiences.setdefault(f"root:{root}", []).append(experience.experience_id)

        for members in source_to_experiences.values():
            anchor = members[0]
            for other in members[1:]:
                uf.union(anchor, other)

        # Declared family keys also unite members even when source ids differ.
        by_declared: Dict[str, List[str]] = {}
        for experience in experiences:
            by_declared.setdefault(experience.source_family_key, []).append(experience.experience_id)
        for members in by_declared.values():
            anchor = members[0]
            for other in members[1:]:
                uf.union(anchor, other)

        components: Dict[str, List[InvestigationExperience]] = {}
        for experience in experiences:
            components.setdefault(uf.find(experience.experience_id), []).append(experience)

        families: List[SourceFamily] = []
        mapping: Dict[str, str] = {}
        for members in components.values():
            keys = sorted({item.source_family_key for item in members})
            family_key = keys[0]
            family_id = f"family:{family_key}" if len(keys) == 1 else "family:" + "+".join(keys)
            shared = sorted(
                {
                    source
                    for item in members
                    for source in item.upstream_source_ids
                }
            )
            rationale = (
                f"Grouped {len(members)} experience(s) by declared lineage {keys} "
                f"and shared upstream sources {shared or ['none']}. "
                "Shared lineage is one observation family, not N independent cases."
            )
            family = SourceFamily(
                family_id=family_id,
                family_key=family_key,
                member_investigation_ids=sorted({item.investigation_id for item in members}),
                member_experience_ids=sorted(item.experience_id for item in members),
                shared_source_ids=shared,
                rationale=rationale,
            )
            families.append(family)
            for item in members:
                mapping[item.experience_id] = family_id

        families.sort(key=lambda fam: fam.family_id)
        return SourceFamilyClustering(
            families=families,
            experience_to_family=mapping,
            algorithm=cls.ALGORITHM,
        )
