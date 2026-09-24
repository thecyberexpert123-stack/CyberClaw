"""Capability definitions representing domain-agnostic or specialist actions."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Capability(BaseModel):
    """A defined functional ability within CyberClaw.

    Capabilities represent WHAT can be done, abstracted away from HOW
    a specific tool or provider executes it.
    """

    id: str = Field(description="Unique capability identifier, e.g. 'discovery.entity'")
    name: str = Field(description="Human-readable capability name")
    description: str = Field(default="")
    category: str = Field(default="general", description="Functional category or ecosystem name")
    input_schema: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional parameter validation schema"
    )
    output_schema: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional expected output schema"
    )
    required_permissions: List[str] = Field(
        default_factory=list, description="Permissions required to invoke this capability"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)
