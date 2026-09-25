"""Thread-safe, versioned Policy Registry for CyberClaw."""

from __future__ import annotations

import copy
from typing import Dict, List, Optional
from cyberclaw.authority.versions import semantic_version_key
from cyberclaw.policy.errors import PolicyNotFoundError, PolicyValidationError
from cyberclaw.policy.models import Policy, PolicyEffect
from cyberclaw.policy.rules import create_standard_rules


DEFAULT_POLICY_ID = "default-system-policy"
DEFAULT_POLICY_VERSION = "1.1.0"


def _semantic_version_key(version: str) -> tuple:
    """Order policy versions numerically so 1.10.0 is newer than 1.9.0."""
    return semantic_version_key(version)


class PolicyRegistry:
    """Registry maintaining immutable, versioned authorization policies."""

    def __init__(self, populate_defaults: bool = True) -> None:
        # Structure: {policy_id: {version: Policy}}
        self._policies: Dict[str, Dict[str, Policy]] = {}
        self._default_policy_id: str = DEFAULT_POLICY_ID
        self._read_only: bool = False

        if populate_defaults:
            self._register_default_policy()

    def _register_default_policy(self) -> None:
        """Create and register the authoritative baseline system policy."""
        default_policy = Policy(
            policy_id=DEFAULT_POLICY_ID,
            name="Authoritative System Authorization Policy",
            version=DEFAULT_POLICY_VERSION,
            description="Baseline fail-closed, role- and risk-aware policy governing CyberClaw execution.",
            default_effect=PolicyEffect.DENY,
            rules=create_standard_rules(),
            metadata={"origin": "core_system", "system_protected": True},
        )
        self.register_policy(default_policy)

    def register_policy(self, policy: Policy) -> None:
        """Register a versioned policy. Once registered, that specific version is immutable."""
        if self._read_only:
            raise PolicyValidationError("PolicyRegistry is in read-only / branch-isolated mode; cannot mutate policies.")

        if not policy.policy_id or not policy.policy_id.strip():
            raise PolicyValidationError("Policy ID cannot be empty.")
        if not policy.version or not policy.version.strip():
            raise PolicyValidationError("Policy version cannot be empty.")

        pid = policy.policy_id.strip()
        pver = policy.version.strip()

        if pid not in self._policies:
            self._policies[pid] = {}

        if pver in self._policies[pid]:
            existing = self._policies[pid][pver]
            if existing == policy:
                return  # Identical registration is idempotent
            raise PolicyValidationError(
                f"Policy '{pid}' version '{pver}' is already registered and immutable."
            )

        self._policies[pid][pver] = policy

    def get_policy(self, policy_id: str, version: Optional[str] = None) -> Policy:
        """Retrieve a policy by ID and optional version.

        If version is omitted, returns the latest registered version.
        """
        pid = policy_id.strip()
        if pid not in self._policies or not self._policies[pid]:
            raise PolicyNotFoundError(f"Policy '{pid}' not found in registry.", policy_id=pid)

        versions_map = self._policies[pid]
        if version:
            v_clean = version.strip()
            if v_clean not in versions_map:
                raise PolicyNotFoundError(
                    f"Version '{v_clean}' of policy '{pid}' not found.", policy_id=pid
                )
            return versions_map[v_clean]

        # Latest means highest semantic version, not lexicographic order.
        # "1.10.0" must outrank "1.9.0".
        sorted_versions = sorted(versions_map.keys(), key=_semantic_version_key)
        return versions_map[sorted_versions[-1]]

    def get_default_policy(self) -> Policy:
        """Retrieve the current active default policy."""
        return self.get_policy(self._default_policy_id)

    def set_default_policy(self, policy_id: str) -> None:
        """Set the active default policy ID."""
        if self._read_only:
            raise PolicyValidationError("Cannot change default policy in read-only mode.")
        if policy_id not in self._policies:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.", policy_id=policy_id)
        self._default_policy_id = policy_id

    def list_policies(self) -> List[Policy]:
        """Return all registered policy versions."""
        result: List[Policy] = []
        for pid in sorted(self._policies.keys()):
            for v in sorted(self._policies[pid].keys()):
                result.append(self._policies[pid][v])
        return result

    def has_policy(self, policy_id: str, version: Optional[str] = None) -> bool:
        """Check if policy exists."""
        pid = policy_id.strip()
        if pid not in self._policies:
            return False
        if version:
            return version.strip() in self._policies[pid]
        return bool(self._policies[pid])

    def create_isolated_snapshot(self) -> PolicyRegistry:
        """Create a deep-copied, read-only isolated snapshot for counterfactual branches."""
        isolated = PolicyRegistry(populate_defaults=False)
        isolated._policies = copy.deepcopy(self._policies)
        isolated._default_policy_id = self._default_policy_id
        isolated._read_only = True
        return isolated
