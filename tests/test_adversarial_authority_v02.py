"""Adversarial authority probes for security-contract hardening v0.2.

Probes run through the real execution, policy, replay, branch, correlation,
and knowledge APIs. Simulated providers only. A caller boolean or an arbitrary
token is not an approval record. Entity identity is type plus name.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import CapabilityTrustError
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.provider import CapabilityProvider
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.knowledge.materialization import KnowledgeMaterializer
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.errors import (
    ApprovalRequiredError,
    AuthorizationDeniedError,
    PolicyValidationError,
    SupervisionRequiredError,
)
from cyberclaw.policy.models import ActorRole, AuthorizationDecisionType, PolicyExecutionContext
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.types import (
    Entity,
    EntityIdentityError,
    Source,
    entity_storage_key,
    has_entity,
    normalize_entity_index,
)


class SimProvider(CapabilityProvider):
    def __init__(self, capability_id: str) -> None:
        super().__init__(id=f"provider.{capability_id}", name="sim", capability_id=capability_id)
        self.calls = 0

    def is_ready(self, context=None):
        return True, None

    def execute(self, parameters, context):
        self.calls += 1
        evidence = Evidence(
            type="simulated_observation",
            subject="simulated",
            value={"status": "ok"},
            source=Source(type="mock", name=self.id),
        )
        return ExecutionResult.success(output={"status": "ok"}, evidence=[evidence])


def _core(tmp_path: Path) -> CyberClawCore:
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    for actor in ("analyst.ada", "analyst.bea", "lead.sam", "operator.bob"):
        core.permissions.grant_permission(actor, "investigation:view")
        core.permissions.grant_permission(actor, "investigation:update")
    core.permissions.assign_role("analyst.ada", "analyst")
    core.permissions.assign_role("analyst.bea", "analyst")
    return core


def _capability(core: CyberClawCore, capability_id: str, trust: CapabilityTrustState, scope: ActionScope) -> tuple:
    capability = Capability(
        id=capability_id,
        name=capability_id,
        action_scope=scope,
        lifecycle_state=CapabilityLifecycleState.TRUSTED,
        trust_state=trust,
    )
    core.register_capability(capability)
    provider = SimProvider(capability_id)
    core.register_provider(provider)
    return capability, provider


def _case(core: CyberClawCore, title: str):
    investigation = core.create_investigation(title)
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="start")
    return investigation


def _issue(core: CyberClawCore, investigation, capability, actor: str, scope: ActionScope, approver: str = "lead.sam", expires_at=None):
    decision = core.policy_engine.authorize(
        PolicyExecutionContext(
            investigation_id=investigation.id,
            case_stage=investigation.current_state.value,
            actor_id=actor,
            actor_role=core._resolve_actor_role(actor),
            capability_id=capability.id,
            capability_version=capability.version,
            action_scope=scope.value,
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
        )
    )
    assert decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL
    approved = core.policy_engine.request_approval(
        decision_id=decision.decision_id,
        approver_id=approver,
        approver_role=ActorRole.LEAD_INVESTIGATOR.value,
        expires_at=expires_at,
    )
    return approved.context_snapshot["approval_token"], approved


def test_self_granted_boolean_does_not_execute(tmp_path: Path):
    core = _core(tmp_path)
    capability, provider = _capability(core, "sim.destroy", CapabilityTrustState.FULLY_TRUSTED, ActionScope.DESTRUCTIVE)
    investigation = _case(core, "boolean")
    with pytest.raises(ApprovalRequiredError) as exc:
        core.execute_action(
            investigation.id,
            capability.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_granted=True,
        )
    decision = core.policy_engine.get_decision(exc.value.decision_id)
    assert decision is not None
    assert decision.context_snapshot.get("approval_token") is None
    assert decision.is_authorized is False
    assert provider.calls == 0


def test_arbitrary_token_is_not_an_approval_record(tmp_path: Path):
    core = _core(tmp_path)
    capability, provider = _capability(core, "sim.destroy", CapabilityTrustState.FULLY_TRUSTED, ActionScope.DESTRUCTIVE)
    investigation = _case(core, "arbitrary")
    with pytest.raises(ApprovalRequiredError) as exc:
        core.execute_action(
            investigation.id,
            capability.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_token="granted",
        )
    assert "Approval validation rejected token: no approval record" in str(exc.value)
    assert provider.calls == 0

    # System administration skips the permission boolean. Policy must still reject it.
    with pytest.raises(ApprovalRequiredError) as system_exc:
        core.execute_action(
            investigation.id,
            capability.id,
            {},
            actor="core.system",
            scope=ActionScope.DESTRUCTIVE,
            approval_granted=True,
            approval_token="granted",
        )
    assert "no approval record" in str(system_exc.value)
    assert provider.calls == 0


def test_valid_external_approval_executes_and_wrong_tokens_do_not(tmp_path: Path):
    core = _core(tmp_path)
    capability, provider = _capability(core, "sim.destroy", CapabilityTrustState.FULLY_TRUSTED, ActionScope.DESTRUCTIVE)
    other, other_provider = _capability(core, "sim.other", CapabilityTrustState.FULLY_TRUSTED, ActionScope.DESTRUCTIVE)
    investigation = _case(core, "valid")
    other_case = _case(core, "other-case")
    token, approved = _issue(core, investigation, capability, "analyst.ada", ActionScope.DESTRUCTIVE)
    assert approved.is_authorized is True

    result = core.execute_action(
        investigation.id,
        capability.id,
        {},
        actor="analyst.ada",
        scope=ActionScope.DESTRUCTIVE,
        approval_token=token,
    )
    assert result.is_success is True
    assert provider.calls == 1

    with pytest.raises(ApprovalRequiredError) as wrong:
        core.execute_action(
            investigation.id,
            capability.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_token="not-the-issued-token",
        )
    assert "no approval record" in str(wrong.value)
    assert provider.calls == 1

    with pytest.raises(ApprovalRequiredError) as other_cap:
        core.execute_action(
            investigation.id,
            other.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_token=token,
        )
    assert "different capability" in str(other_cap.value)
    assert other_provider.calls == 0

    with pytest.raises(ApprovalRequiredError) as other_case_exc:
        core.execute_action(
            other_case.id,
            capability.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_token=token,
        )
    assert "different case" in str(other_case_exc.value)
    assert provider.calls == 1

    with pytest.raises(ApprovalRequiredError) as other_actor:
        core.execute_action(
            investigation.id,
            capability.id,
            {},
            actor="analyst.bea",
            scope=ActionScope.DESTRUCTIVE,
            approval_token=token,
        )
    assert "different requester" in str(other_actor.value)

    capability.version = "2.0.0"
    with pytest.raises(ApprovalRequiredError) as other_version:
        core.execute_action(
            investigation.id,
            capability.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_token=token,
        )
    assert "different capability version" in str(other_version.value)
    assert provider.calls == 1

    mismatched = core.policy_engine.authorize(
        PolicyExecutionContext(
            investigation_id=investigation.id,
            case_stage=investigation.current_state.value,
            actor_id="analyst.ada",
            actor_role=ActorRole.ANALYST.value,
            capability_id=capability.id,
            capability_version="1.0.0",
            action_scope="irreversible",
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=CapabilityTrustState.FULLY_TRUSTED.value,
            approval_token=token,
        )
    )
    assert mismatched.is_authorized is False
    assert any("different scope" in reason for reason in mismatched.reasons)


def test_expired_approval_is_rejected(tmp_path: Path):
    core = _core(tmp_path)
    capability, provider = _capability(core, "sim.destroy", CapabilityTrustState.FULLY_TRUSTED, ActionScope.DESTRUCTIVE)
    investigation = _case(core, "expired")
    token, approved = _issue(
        core,
        investigation,
        capability,
        "analyst.ada",
        ActionScope.DESTRUCTIVE,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=5),
    )
    assert approved.is_authorized is False
    with pytest.raises(ApprovalRequiredError) as exc:
        core.execute_action(
            investigation.id,
            capability.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_token=token,
        )
    assert "approval record expired" in str(exc.value)
    assert provider.calls == 0


def test_unauthorized_role_and_proposer_cannot_approve(tmp_path: Path):
    core = _core(tmp_path)
    capability, _provider = _capability(core, "sim.destroy", CapabilityTrustState.FULLY_TRUSTED, ActionScope.DESTRUCTIVE)
    investigation = _case(core, "approver")
    decision = core.policy_engine.authorize(
        PolicyExecutionContext(
            investigation_id=investigation.id,
            case_stage=investigation.current_state.value,
            actor_id="analyst.ada",
            actor_role=ActorRole.ANALYST.value,
            capability_id=capability.id,
            capability_version=capability.version,
            action_scope="destructive",
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
        )
    )
    with pytest.raises(PolicyValidationError) as role_exc:
        core.policy_engine.request_approval(
            decision.decision_id,
            approver_id="analyst.bea",
            approver_role=ActorRole.ANALYST.value,
        )
    assert "lacks authority to approve" in str(role_exc.value)

    own = core.policy_engine.authorize(
        PolicyExecutionContext(
            investigation_id=investigation.id,
            case_stage=investigation.current_state.value,
            actor_id="lead.sam",
            actor_role=ActorRole.LEAD_INVESTIGATOR.value,
            capability_id=capability.id,
            capability_version=capability.version,
            action_scope="destructive",
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
        )
    )
    with pytest.raises(PolicyValidationError) as proposer_exc:
        core.policy_engine.request_approval(
            own.decision_id,
            approver_id="lead.sam",
            approver_role=ActorRole.LEAD_INVESTIGATOR.value,
        )
    assert "cannot approve their own proposal" in str(proposer_exc.value)


def test_provisional_high_impact_is_denied_even_with_approval(tmp_path: Path):
    core = _core(tmp_path)
    investigation = _case(core, "provisional")
    consequential, consequential_provider = _capability(
        core, "sim.provisional.consequential", CapabilityTrustState.PROVISIONAL, ActionScope.CONSEQUENTIAL
    )
    destructive, destructive_provider = _capability(
        core, "sim.provisional.destructive", CapabilityTrustState.PROVISIONAL, ActionScope.DESTRUCTIVE
    )
    with pytest.raises(AuthorizationDeniedError) as consequential_exc:
        core.execute_action(
            investigation.id,
            consequential.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.CONSEQUENTIAL,
            approval_granted=True,
            approval_token="granted",
            supervision_acknowledged=True,
        )
    assert "R007-DENY-PROVISIONAL-HIGH-IMPACT" in str(consequential_exc.value)
    assert consequential_provider.calls == 0

    with pytest.raises(AuthorizationDeniedError) as destructive_exc:
        core.execute_action(
            investigation.id,
            destructive.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_granted=True,
            approval_token="granted",
        )
    assert "R007-DENY-PROVISIONAL-HIGH-IMPACT" in str(destructive_exc.value)
    assert destructive_provider.calls == 0

    # A grant issued while the capability was fully trusted must not survive a downgrade.
    trusted, trusted_provider = _capability(
        core, "sim.downgrade", CapabilityTrustState.FULLY_TRUSTED, ActionScope.DESTRUCTIVE
    )
    token, _approved = _issue(core, investigation, trusted, "analyst.ada", ActionScope.DESTRUCTIVE)
    trusted.trust_state = CapabilityTrustState.PROVISIONAL
    with pytest.raises(AuthorizationDeniedError) as downgrade_exc:
        core.execute_action(
            investigation.id,
            trusted.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.DESTRUCTIVE,
            approval_token=token,
        )
    assert "R007-DENY-PROVISIONAL-HIGH-IMPACT" in str(downgrade_exc.value)
    assert trusted_provider.calls == 0


def test_trust_matrix_does_not_invent_denials(tmp_path: Path):
    core = _core(tmp_path)
    investigation = _case(core, "matrix")

    for trust in (CapabilityTrustState.UNTRUSTED, CapabilityTrustState.REVOKED):
        capability, provider = _capability(core, f"sim.{trust.value}", trust, ActionScope.REVERSIBLE)
        with pytest.raises(CapabilityTrustError):
            core.execute_action(investigation.id, capability.id, {}, actor="analyst.ada", scope=ActionScope.REVERSIBLE)
        assert provider.calls == 0

    provisional, provisional_provider = _capability(
        core, "sim.provisional.reversible", CapabilityTrustState.PROVISIONAL, ActionScope.REVERSIBLE
    )
    with pytest.raises(AuthorizationDeniedError) as reversible_exc:
        core.execute_action(
            investigation.id,
            provisional.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.REVERSIBLE,
        )
    decision = core.policy_engine.get_decision(reversible_exc.value.decision_id)
    assert decision is not None
    assert "R007-DENY-PROVISIONAL-HIGH-IMPACT" not in decision.matched_rules
    assert provisional_provider.calls == 0

    trusted, trusted_provider = _capability(
        core, "sim.trusted.reversible", CapabilityTrustState.TRUSTED_WITH_SCOPE, ActionScope.REVERSIBLE
    )
    result = core.execute_action(
        investigation.id,
        trusted.id,
        {},
        actor="analyst.ada",
        scope=ActionScope.REVERSIBLE,
    )
    assert result.is_success is True
    assert trusted_provider.calls == 1

    consequential, consequential_provider = _capability(
        core, "sim.trusted.consequential", CapabilityTrustState.TRUSTED_WITH_SCOPE, ActionScope.CONSEQUENTIAL
    )
    with pytest.raises(SupervisionRequiredError):
        core.execute_action(
            investigation.id,
            consequential.id,
            {},
            actor="analyst.ada",
            scope=ActionScope.CONSEQUENTIAL,
            approval_token="granted",
        )
    assert consequential_provider.calls == 0
    supervised = core.execute_action(
        investigation.id,
        consequential.id,
        {},
        actor="analyst.ada",
        scope=ActionScope.CONSEQUENTIAL,
        supervision_acknowledged=True,
    )
    assert supervised.is_success is True
    assert consequential_provider.calls == 1

    lead_result = core.execute_action(
        investigation.id,
        consequential.id,
        {},
        actor="lead.sam",
        actor_role=ActorRole.LEAD_INVESTIGATOR.value,
        scope=ActionScope.CONSEQUENTIAL,
    )
    assert lead_result.is_success is True


def test_entity_identity_survives_storage_replay_branch_knowledge_and_correlation(tmp_path: Path):
    core = _core(tmp_path)
    investigation = _case(core, "entities")
    domain = investigation.add_entity("domain", "example.com", {"kind": "domain"})
    organization = investigation.add_entity("organization", "example.com", {"kind": "org"})
    again = investigation.add_entity("domain", "example.com", {"extra": "kept"})
    assert domain.id != organization.id
    assert again.id == domain.id
    assert again.attributes["extra"] == "kept"
    assert len(investigation.entities) == 2
    assert has_entity(investigation.entities, "example.com", "domain")
    assert has_entity(investigation.entities, "example.com", "organization")
    assert entity_storage_key("domain", "example.com") in investigation.entities
    assert "example.com" not in investigation.entities

    snapshot = investigation.capture_snapshot(trigger="identity")
    replayed = ReplayEngine.replay(investigation)
    assert replayed.verify_against_snapshot(snapshot) is True
    assert has_entity(replayed.entities, "example.com", "domain")
    assert has_entity(replayed.entities, "example.com", "organization")

    serialized = {key: entity.model_dump(mode="json") for key, entity in investigation.entities.items()}
    restored = normalize_entity_index({key: Entity.model_validate(value) for key, value in serialized.items()})
    assert has_entity(restored, "example.com", "domain")
    assert has_entity(restored, "example.com", "organization")

    historical = {
        "example.com": Entity(type="domain", name="example.com", id="hist-domain").model_dump(),
    }
    migrated = normalize_entity_index({key: Entity.model_validate(value) for key, value in historical.items()})
    assert list(migrated) == [entity_storage_key("domain", "example.com")]
    assert migrated[entity_storage_key("domain", "example.com")].id == "hist-domain"
    with pytest.raises(EntityIdentityError):
        normalize_entity_index(
            {
                "a": Entity(type="domain", name="example.com", id="one"),
                "b": Entity(type="domain", name="example.com", id="two"),
            }
        )

    branch = investigation.create_branch(source_snapshot=1, purpose="identity")
    from cyberclaw.branching.engine import BranchEngine

    BranchEngine.simulate_entities(
        branch,
        [
            Entity(type="domain", name="shared.example", id="branch-domain"),
            Entity(type="organization", name="shared.example", id="branch-org"),
        ],
    )
    reconstructed = investigation.replay_branch(branch.branch_id)
    assert has_entity(reconstructed.entities, "shared.example", "domain")
    assert has_entity(reconstructed.entities, "shared.example", "organization")

    investigation.add_evidence(
        Evidence(
            type="dns_resolution",
            subject="example.com",
            value={"records": {"A": ["203.0.113.10"]}},
            source=Source(type="sim", name="dns"),
        )
    )
    core.correlate_investigation(investigation.id)
    assert has_entity(investigation.entities, "example.com", "organization")
    assert has_entity(investigation.entities, "example.com", "domain")
    assert has_entity(investigation.entities, "203.0.113.10", "ip")

    graph = KnowledgeMaterializer.materialize_from_investigation(investigation)
    assert graph.get_node(f"entity:{entity_storage_key('domain', 'example.com')}") is not None
    assert graph.get_node(f"entity:{entity_storage_key('organization', 'example.com')}") is not None
    assert (
        graph.get_node(f"entity:{entity_storage_key('domain', 'example.com')}").node_id
        != graph.get_node(f"entity:{entity_storage_key('organization', 'example.com')}").node_id
    )

    core.workspace.persist_snapshots(investigation.id, [snapshot])
    loaded = core.workspace.load_snapshots(investigation.id)
    assert loaded[0].verify_integrity() is True
    assert loaded[0].metadata.get("entity_index_migrated") is not True
    assert has_entity(loaded[0].entities, "example.com", "domain")

    from cyberclaw.case.models import InvestigationSnapshot

    historical_entity = Entity(type="domain", name="legacy.example", id="legacy")
    historical_snapshot = InvestigationSnapshot(
        investigation_id=investigation.id,
        sequence=99,
        trigger="legacy",
        dfa_state=CoreState.INVESTIGATE.value,
        entities={"legacy.example": historical_entity},
    )
    historical_snapshot.seal()
    core.workspace.persist_snapshots(investigation.id, [historical_snapshot])
    migrated_snapshots = core.workspace.load_snapshots(investigation.id)
    migrated_snapshot = migrated_snapshots[0]
    assert migrated_snapshot.metadata.get("entity_index_migrated") is True
    assert migrated_snapshot.verify_integrity() is True
    assert has_entity(migrated_snapshot.entities, "legacy.example", "domain")
    assert not has_entity(migrated_snapshot.entities, "legacy.example", "organization")
