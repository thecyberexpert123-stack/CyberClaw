"""Authority boundary contract for CyberClaw.

No subsystem gains authority because another subsystem exposes an object,
identifier, result, or path. Submodules record that contract. They do not
authorize, execute, persist, or replay.

This package initializer stays empty so policy and runtime can import a
single helper without creating a second engine or an import cycle.
"""
