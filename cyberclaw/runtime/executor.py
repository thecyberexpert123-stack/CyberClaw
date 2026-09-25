"""Runtime Executor orchestrating governed, policy-aware, and idempotent execution."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, Optional
from uuid import uuid4
from cyberclaw.authority.models import ProviderOutcome
from cyberclaw.authority.outcomes import classify_provider_result, explicit_temporary_failure
from cyberclaw.authority.resolution import execution_boundary
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.case.models import JournalEntryType
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.investigation import Investigation
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.policy.models import (
    AuthorizationDecisionType,
    PolicyExecutionContext,
)
from cyberclaw.runtime.dispatcher import SpecialistDispatcher
from cyberclaw.runtime.errors import (
    BranchExecutionBlockedError,
    DispatchError,
    ProviderExecutionError,
    RuntimeAuthorizationError,
    RuntimeResultValidationError,
    RuntimeTimeoutError,
    RuntimeValidationError,
    UnknownExecutionStateError,
)
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import (
    ExecutionState,
    RuntimeTask,
    TaskStatus,
    utc_now,
)
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.state import TaskLifecycleDFA
from cyberclaw.validation.pipeline import ValidationPipeline


class RuntimeExecutor:
    """Orchestrates end-to-end task execution adhering to strict governance invariants."""

    def __init__(
        self,
        capabilities: CapabilityRegistry,
        policy_engine: PolicyEngine,
        dispatcher: SpecialistDispatcher,
        queue: DurableTaskQueue,
        idempotency_registry: IdempotencyRegistry,
    ) -> None:
        self.capabilities = capabilities
        self.policy_engine = policy_engine
        self.dispatcher = dispatcher
        self.queue = queue
        self.idempotency = idempotency_registry

    def execute_task(
        self,
        task: RuntimeTask,
        investigation: Investigation,
        permission_manager: PermissionManager,
        custom_lesson: Optional[str] = None,
        event_bus: Optional[Any] = None,
        experience_store: Optional[Any] = None,
    ) -> RuntimeTask:
        """Execute a claimed task through the complete governed execution pipeline."""
        # 0. Branch isolation enforcement
        if task.is_counterfactual or getattr(investigation, "is_branch", False):
            self.queue.fail(task.task_id, "Branch tasks cannot execute real providers", failure_type="BRANCH_EXECUTION_BLOCKED")
            raise BranchExecutionBlockedError(
                f"Task '{task.task_id}' cannot execute real providers in counterfactual branch.",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            )

        # 1. Idempotency Check (Duplicate Execution Protection)
        existing_exec = self.idempotency.get_existing_execution(task.idempotency_key)
        if existing_exec:
            # Reconcile completed execution through DFA without re-invoking provider
            TaskLifecycleDFA.transition(task, TaskStatus.AUTHORIZED)
            TaskLifecycleDFA.transition(task, TaskStatus.DISPATCHED)
            TaskLifecycleDFA.transition(task, TaskStatus.RUNNING)
            task.execution_state = ExecutionState.COMPLETED
            self.queue.ack(task.task_id, result=existing_exec.get("result"))
            return task

        # 2. Timeout check before commencing
        if task.timeout_seconds and not task.deadline:
            task.deadline = task.created_at + timedelta(seconds=task.timeout_seconds)

        if task.deadline and utc_now() > task.deadline:
            task.metadata["provider_outcome"] = ProviderOutcome.TIMEOUT_BEFORE_EXECUTION.value
            self.queue.fail(task.task_id, "Deadline expired before execution started", failure_type="TIMEOUT")
            raise RuntimeTimeoutError(
                f"Task '{task.task_id}' timed out before execution.",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            )

        # 3. Capability Resolution & Lifecycle / Trust Verification
        capability = self.capabilities.get_capability(task.capability_id)
        if not capability:
            # A queued task must not manufacture a capability. Existence is not authority.
            self.queue.reject(task.task_id, reason="UNREGISTERED_CAPABILITY")
            raise RuntimeValidationError(
                f"Capability '{task.capability_id}' is not registered. Runtime will not create it.",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
                boundary="NOT_FOUND",
            )

        boundary = execution_boundary(capability)
        if boundary:
            if boundary == "NOT_TRUSTED":
                reason = (
                    f"Capability '{capability.versioned_id}' has trust state "
                    f"'{capability.trust_state.value}' and cannot be executed."
                )
            else:
                reason = (
                    f"Capability '{capability.versioned_id}' is in lifecycle state "
                    f"'{capability.lifecycle_state.value}' and cannot be executed."
                )
            self.queue.reject(task.task_id, reason=reason)
            raise RuntimeValidationError(
                reason,
                task_id=task.task_id,
                investigation_id=task.investigation_id,
                boundary=boundary,
            )

        # 4. Contextual Policy Authorization Evaluation
        try:
            scope_enum = ActionScope(task.action_scope)
        except ValueError:
            scope_enum = ActionScope.CONSEQUENTIAL

        policy_ctx = PolicyExecutionContext(
            investigation_id=task.investigation_id,
            case_stage=investigation.current_state.value,
            actor_id=task.actor,
            actor_role=task.actor_role,
            capability_id=capability.id,
            capability_version=capability.version,
            action_type="execute",
            action_scope=scope_enum.value,
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
            parameters=task.parameters,
            is_branch=False,
        )

        auth_decision = self.policy_engine.authorize(policy_ctx)
        task.authorization_decision_id = auth_decision.decision_id
        task.risk_level = auth_decision.risk_assessment.overall_risk.value
        self.policy_engine.record_in_journal(auth_decision, investigation.case_manager)
        authority_snapshot = {
            "decision_id": auth_decision.decision_id,
            "decision": auth_decision.decision.value,
            "policy_id": auth_decision.policy_id,
            "policy_version": auth_decision.policy_version,
            "capability_id": capability.id,
            "capability_version": capability.version,
            "lifecycle_state": capability.lifecycle_state.value,
            "trust_state": capability.trust_state.value,
            "action_scope": scope_enum.value,
            "actor": task.actor,
            "investigation_id": task.investigation_id,
            "task_id": task.task_id,
        }
        task.metadata["authority"] = authority_snapshot
        self.idempotency.record_authorization(task.idempotency_key, authority_snapshot)

        if not auth_decision.is_authorized:
            if auth_decision.decision in (
                AuthorizationDecisionType.REQUIRE_APPROVAL,
                AuthorizationDecisionType.REQUIRE_SUPERVISION,
                AuthorizationDecisionType.DEFER,
            ):
                self.queue.defer(task.task_id, reason=f"Awaiting authorization ({auth_decision.decision.value})")
                return task
            else:
                reason_str = "; ".join(auth_decision.reasons)
                self.queue.reject(task.task_id, reason=reason_str)
                raise RuntimeAuthorizationError(
                    f"Policy denied task execution: {reason_str}",
                    task_id=task.task_id,
                    investigation_id=task.investigation_id,
                )

        # Transition to AUTHORIZED
        TaskLifecycleDFA.transition(task, TaskStatus.AUTHORIZED)

        # 5. Multi-Phase ValidationPipeline (Schema, Permissions, DFA)
        allowed_dfa_states = [CoreState.READY, CoreState.CLASSIFY, CoreState.INVESTIGATE, CoreState.VERIFY]
        try:
            ValidationPipeline.validate_request(
                capability=capability,
                parameters=task.parameters,
                actor=task.actor,
                permission_manager=permission_manager,
                current_state=investigation.current_state,
                allowed_states=allowed_dfa_states,
                scope=scope_enum,
                approval_granted=True if auth_decision.is_authorized else False,
                policy_decision=auth_decision,
            )
        except Exception as ve:
            self.queue.reject(task.task_id, reason=str(ve))
            raise RuntimeValidationError(
                f"Validation failed: {ve}",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            ) from ve

        # Advance investigation DFA state if appropriate
        if investigation.current_state in (CoreState.READY, CoreState.CLASSIFY):
            investigation.dfa.transition(CoreState.INVESTIGATE, event="runtime.action_started")
            investigation.case_manager.record_state_transition(
                from_state=CoreState.READY.value,
                to_state=CoreState.INVESTIGATE.value,
                event="runtime.action_started",
            )

        # 6. Specialist Dispatch & Provider Execution
        TaskLifecycleDFA.transition(task, TaskStatus.DISPATCHED)
        TaskLifecycleDFA.transition(task, TaskStatus.RUNNING)
        task.execution_state = ExecutionState.IN_PROGRESS

        exec_ctx = ExecutionContext(
            execution_id=str(uuid4()),
            investigation_id=task.investigation_id,
            correlation_id=task.correlation_id or task.investigation_id,
            actor=task.actor,
            granted_permissions=list(permission_manager.get_effective_permissions(task.actor)),
            environment={"state": investigation.current_state.value, "runtime": True},
        )

        try:
            result, resolved_subsystem = self.dispatcher.dispatch(task, exec_ctx)
        except ProviderExecutionError as pee:
            # An exception that escaped dispatch does not prove the provider did not run.
            task.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
            task.metadata["provider_outcome"] = ProviderOutcome.PROVIDER_EXECUTION_EXCEPTION.value
            self.queue.fail(
                task.task_id,
                pee.message,
                failure_type="UNKNOWN_EXECUTION_STATE",
            )
            raise

        # A deadline crossing after dispatch means invocation may have started.
        # Do not treat that as a safe timeout, and do not ack the returned result.
        if task.deadline and utc_now() > task.deadline:
            task.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
            task.metadata["provider_outcome"] = ProviderOutcome.TIMEOUT_WITH_UNKNOWN_EXECUTION.value
            self.queue.fail(
                task.task_id,
                "Deadline exceeded after execution started; provider state unknown",
                failure_type="UNKNOWN_EXECUTION_STATE",
            )
            raise UnknownExecutionStateError(
                f"Task '{task.task_id}' timed out after execution started.",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            )

        outcome = classify_provider_result(result)
        task.metadata["provider_outcome"] = outcome.value
        if outcome in (ProviderOutcome.PROVIDER_EXECUTION_EXCEPTION, ProviderOutcome.UNKNOWN_EXECUTION_STATE):
            task.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
            self.queue.fail(
                task.task_id,
                result.error or "Provider state unknown after invocation",
                failure_type="UNKNOWN_EXECUTION_STATE",
            )
            raise ProviderExecutionError(
                f"Provider exception during capability '{task.capability_id}': {result.error}",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
                is_retryable=False,
            )
        if outcome == ProviderOutcome.MALFORMED_RESULT:
            task.execution_state = ExecutionState.COMPLETED
            self.queue.fail(
                task.task_id,
                "Provider returned a malformed result",
                failure_type="MALFORMED_RESULT",
            )
            raise RuntimeResultValidationError(
                f"Malformed result from capability '{task.capability_id}'",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            )
        if outcome in (ProviderOutcome.PROVIDER_REJECTION, ProviderOutcome.VALIDATION_FAILURE):
            task.execution_state = ExecutionState.UNSTARTED
            failure_type = (
                "VALIDATION_FAILURE" if outcome == ProviderOutcome.VALIDATION_FAILURE else "PROVIDER_REJECTION"
            )
            self.queue.fail(task.task_id, result.error or failure_type, failure_type=failure_type)
            raise DispatchError(
                f"Capability '{task.capability_id}' was not invoked: {result.error}",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            )

        # 7. Post-Execution Result Validation
        try:
            ValidationPipeline.validate_result(result)
        except Exception as rve:
            task.execution_state = ExecutionState.COMPLETED
            self.queue.fail(task.task_id, f"Malformed execution result: {rve}", failure_type="MALFORMED_RESULT")
            raise RuntimeResultValidationError(
                f"Result validation failed: {rve}",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            ) from rve

        # 8. Evidence Ingestion
        if result.is_success and result.evidence:
            for ev in result.evidence:
                if not ev.provenance.investigation_id:
                    ev.provenance.investigation_id = task.investigation_id
                if not ev.provenance.specialist_id and resolved_subsystem:
                    ev.provenance.specialist_id = resolved_subsystem
                if not ev.provenance.capability_id:
                    ev.provenance.capability_id = task.capability_id
                investigation.add_evidence(ev)

        # 9. Case Journal & Execution History Recording
        investigation.case_manager.record_execution(
            requirement_id=task.requirement_id or str(uuid4()),
            specialist_id=resolved_subsystem,
            capability_id=task.capability_id,
            capability_version=capability.version,
            status=result.status.value,
            duration_ms=result.duration_ms,
            evidence_count=len(result.evidence),
            evidence_ids=[e.id for e in result.evidence],
            error=result.error,
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
            permission_scope=scope_enum.value,
            action_scope=scope_enum.value,
            authorization_decision_id=auth_decision.decision_id,
            risk_level=auth_decision.risk_assessment.overall_risk.value,
            policy_id=auth_decision.policy_id,
            policy_version=auth_decision.policy_version,
            decision=auth_decision.decision.value,
            actor=task.actor,
            task_id=task.task_id,
            provider_id=resolved_subsystem,
            provider_outcome=task.metadata.get("provider_outcome"),
            investigation_id=task.investigation_id,
        )

        # Handle unsuccessful provider execution
        if not result.completed_normally:
            task.execution_state = ExecutionState.COMPLETED
            err_msg = result.error or "Provider returned failure status"
            retryable = explicit_temporary_failure(result)
            failure_type = "PROVIDER_TEMPORARY_FAILURE" if retryable else "PROVIDER_FAILURE"
            self.queue.fail(task.task_id, err_msg, failure_type=failure_type)
            raise ProviderExecutionError(
                f"Execution failed on capability '{task.capability_id}': {err_msg}",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
                is_retryable=retryable,
            )

        # 10. Experience Recording
        if experience_store is not None:
            lesson = custom_lesson or f"Executed capability '{task.capability_id}' via runtime with status {result.status.value}"
            experience_store.record(
                action=f"runtime_execute:{task.capability_id}",
                context={"parameters": task.parameters, "investigation_id": task.investigation_id},
                result=result,
                lesson=lesson,
                conditions=task.parameters,
                scope=f"capability:{task.capability_id}",
                investigation_id=task.investigation_id,
            )

        # 11. Idempotency Registration & Queue Acknowledgment
        task.execution_state = ExecutionState.COMPLETED
        result_dict = result.model_dump()
        self.idempotency.record_execution(task.idempotency_key, {"result": result_dict, "status": result.status.value})
        self.queue.ack(task.task_id, result=result_dict)
        return task
