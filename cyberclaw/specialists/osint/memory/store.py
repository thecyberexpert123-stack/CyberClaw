"""Local memory and experience systems for the OSINT Specialist."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.memory.memory import MemoryStore
from cyberclaw.memory.store import ExperienceStore


class OSINTLocalMemory:
    """Specialist-local working memory for target classification and cached facts."""

    def __init__(self, investigation_id: Optional[str] = None) -> None:
        self._store = MemoryStore(investigation_id=investigation_id)

    def cache_target_info(self, target: str, info: Dict[str, Any]) -> None:
        self._store.set(f"target:{target}", info, tags=["target_profile"])

    def get_target_info(self, target: str) -> Optional[Dict[str, Any]]:
        return self._store.get(f"target:{target}")

    def list_all_facts(self) -> List[Any]:
        return self._store.list_all()

    def clear(self) -> None:
        self._store.clear()


class OSINTExperienceStore:
    """Specialist-local experience store recording provider reliability and lessons."""

    def __init__(self, investigation_id: Optional[str] = None) -> None:
        self._store = ExperienceStore(investigation_id=investigation_id)

    def record_provider_run(
        self,
        capability_id: str,
        provider_id: str,
        target: str,
        result: ExecutionResult,
        custom_lesson: Optional[str] = None,
        conditions: Optional[Dict[str, Any]] = None,
        investigation_id: Optional[str] = None,
    ) -> ExperienceRecord:
        """Record operational experience of executing an OSINT provider."""
        conds = conditions or {"target": target, "provider_id": provider_id}

        if custom_lesson:
            lesson = custom_lesson
        elif result.is_success:
            lesson = (
                f"Provider '{provider_id}' successfully retrieved intelligence for target '{target}'."
            )
        elif result.is_empty:
            lesson = (
                f"Provider '{provider_id}' succeeded with zero findings for target '{target}'."
            )
        else:
            lesson = (
                f"Provider '{provider_id}' failed for target '{target}' due to '{result.error}'; "
                f"evaluate provider readiness or alternative provider before retrying."
            )

        return self._store.record(
            action=f"osint.execute:{provider_id}",
            context={"capability_id": capability_id, "provider_id": provider_id, "target": target},
            result=result,
            lesson=lesson,
            conditions=conds,
            scope=f"osint.provider:{provider_id}",
            investigation_id=investigation_id,
        )

    def get_provider_experiences(self, provider_id: str) -> List[ExperienceRecord]:
        return self._store.find_by_scope(f"osint.provider:{provider_id}")

    def list_all(self, include_superseded: bool = False) -> List[ExperienceRecord]:
        return self._store.list_all(include_superseded=include_superseded)
