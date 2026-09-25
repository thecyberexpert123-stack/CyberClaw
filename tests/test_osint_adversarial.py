"""Adversarial checks for the governed OSINT vertical.

These tests use the existing lifecycle, trust, permission, and policy gates.
They do not add an OSINT authorization model.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberclaw.capabilities.errors import (
    CapabilityNotFoundError,
    CapabilityTrustError,
    CapabilityUnavailableError,
)
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.core import CyberClawCore
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.errors import AuthorizationDeniedError
from cyberclaw.specialists.endpoint import SpecialistRequest
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_DNS_LOOKUP,
    get_osint_capabilities,
)
from cyberclaw.specialists.osint.governance import configure_governed_osint
from cyberclaw.specialists.osint.providers.fixtures import APEX_DOMAIN
from cyberclaw.validation.errors import PolicyValidationError


def _build(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()
    specialist = configure_governed_osint(tmp_path / "osint")
    for capability in get_osint_capabilities():
        core.register_capability(capability)
    core.register_specialist(specialist.as_specialist())
    investigation = core.create_investigation("OSINT adversarial")
    return core, specialist, investigation


def _dns_calls(specialist) -> int:
    return sum(provider.calls for provider in specialist._providers[CAPABILITY_DNS_LOOKUP])


def test_direct_provider_and_specialist_invocation_are_blocked(tmp_path: Path):
    core, specialist, investigation = _build(tmp_path)
    provider = specialist._providers[CAPABILITY_DNS_LOOKUP][0]
    direct = provider.execute({"target": APEX_DOMAIN}, ExecutionContext(investigation_id=investigation.id))
    assert direct.is_failure
    assert direct.error_code == "UNGOVERNED_PROVIDER_INVOCATION"
    assert provider.calls == 0
    assert investigation.evidence_store.count() == 0

    response = specialist.invoke(
        SpecialistRequest(
            investigation_id=investigation.id,
            capability_id=CAPABILITY_DNS_LOOKUP,
            parameters={"target": APEX_DOMAIN},
            context=ExecutionContext(investigation_id=investigation.id),
        )
    )
    assert response.result.is_failure
    assert response.result.error_code == "UNGOVERNED_PROVIDER_INVOCATION"
    assert provider.calls == 0

    # The same provider runs when the governed executor authorizes it.
    result = core.execute_action(
        investigation.id,
        CAPABILITY_DNS_LOOKUP,
        {"target": APEX_DOMAIN},
    )
    assert result.is_success
    assert provider.calls == 1
    assert investigation.evidence_store.count() >= 1


def test_advertised_unregistered_capability_does_not_execute(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()
    specialist = configure_governed_osint(tmp_path / "osint")
    core.register_specialist(specialist.as_specialist())
    investigation = core.create_investigation("Advertised only")
    with pytest.raises(CapabilityNotFoundError):
        core.execute_action(investigation.id, CAPABILITY_DNS_LOOKUP, {"target": APEX_DOMAIN})
    assert _dns_calls(specialist) == 0
    assert investigation.evidence_store.count() == 0


def test_lifecycle_and_trust_matrix_blocks_before_collection(tmp_path: Path):
    core, specialist, investigation = _build(tmp_path)
    capability = core.capabilities.get_capability(CAPABILITY_DNS_LOOKUP)
    blocked_lifecycle = [
        CapabilityLifecycleState.PROPOSED,
        CapabilityLifecycleState.EXPERIMENTAL,
        CapabilityLifecycleState.VALIDATED,
        CapabilityLifecycleState.DEPRECATED,
        CapabilityLifecycleState.DISABLED,
        CapabilityLifecycleState.RETIRED,
        CapabilityLifecycleState.REJECTED,
    ]
    for state in blocked_lifecycle:
        capability.lifecycle_state = state
        with pytest.raises(CapabilityUnavailableError):
            core.execute_action(investigation.id, CAPABILITY_DNS_LOOKUP, {"target": APEX_DOMAIN})
        assert _dns_calls(specialist) == 0

    capability.lifecycle_state = CapabilityLifecycleState.AVAILABLE
    for state in (CapabilityTrustState.UNTRUSTED, CapabilityTrustState.REVOKED):
        capability.trust_state = state
        with pytest.raises(CapabilityTrustError):
            core.execute_action(investigation.id, CAPABILITY_DNS_LOOKUP, {"target": APEX_DOMAIN})
        assert _dns_calls(specialist) == 0

    capability.trust_state = CapabilityTrustState.PROVISIONAL
    with pytest.raises(AuthorizationDeniedError):
        core.execute_action(investigation.id, CAPABILITY_DNS_LOOKUP, {"target": APEX_DOMAIN})
    assert _dns_calls(specialist) == 0

    capability.trust_state = CapabilityTrustState.TRUSTED_WITH_SCOPE
    capability.action_scope = ActionScope.CONSEQUENTIAL
    capability.trust_state = CapabilityTrustState.PROVISIONAL
    with pytest.raises(AuthorizationDeniedError):
        core.execute_action(investigation.id, CAPABILITY_DNS_LOOKUP, {"target": APEX_DOMAIN})
    assert _dns_calls(specialist) == 0


def test_missing_permission_blocks_before_collection(tmp_path: Path):
    core, specialist, investigation = _build(tmp_path)
    core.permissions.assign_role("analyst.osint", "analyst")
    with pytest.raises(PolicyValidationError):
        core.execute_action(
            investigation.id,
            CAPABILITY_DNS_LOOKUP,
            {"target": APEX_DOMAIN},
            actor="analyst.osint",
        )
    assert _dns_calls(specialist) == 0
    assert investigation.evidence_store.count() == 0


def test_core_runtime_policy_and_replay_do_not_import_osint():
    from pathlib import Path as FilePath

    import cyberclaw.core as core_module
    import cyberclaw.policy.engine as policy_module
    import cyberclaw.replay.engine as replay_module
    import cyberclaw.runtime.executor as runtime_module

    for module in (core_module, policy_module, replay_module, runtime_module):
        text = FilePath(module.__file__).read_text(encoding="utf-8")
        assert "specialists.osint" not in text
        assert "osint.dns_lookup" not in text
