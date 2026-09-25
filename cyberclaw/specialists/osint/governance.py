"""Governed OSINT specialist setup.

This does not authorize, register capabilities, or execute providers.
Core remains responsible for lifecycle, trust, permission, and policy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from cyberclaw.specialists.osint.providers.fixtures import fixture_providers
from cyberclaw.specialists.osint.specialist import OSINTSpecialist


def configure_governed_osint(
    workspace_base: Optional[Path] = None,
) -> OSINTSpecialist:
    """Build the fixture-backed specialist used by the investigation vertical.

    Mock providers are not registered. Direct invocation is refused until the
    governed executor stamps the request. The live provider is not registered.
    """
    specialist = OSINTSpecialist(
        workspace_base=workspace_base,
        use_default_mock_providers=False,
        require_governed_dispatch=True,
    )
    for provider in fixture_providers():
        specialist.register_provider(provider)
    return specialist
