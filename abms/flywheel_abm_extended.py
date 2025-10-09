"""
Deprecated shim module.

The extended ABM has been unified into abms/flywheel_abm.py to provide a
single, readable implementation that includes both the base and extended
models. Import from `flywheel_abm` instead of this module.

This shim re-exports the extended classes for backward compatibility:

    from flywheel_abm import ExtendedFlywheelABM, ExtendedPolicyParams
"""

from .flywheel_abm import (
    ExtendedPolicyParams,
    ExtendedUserProfile,
    ExtendedInteraction,
    ExtendedFlywheelABM,
    # Base exports for convenience
    PolicyParams,
    UserProfile,
    Interaction,
    RecordType,
    License,
    Attribution,
    WorkflowState,
    AgentType,
    JurisdictionType,
)

__all__ = [
    'ExtendedPolicyParams',
    'ExtendedUserProfile',
    'ExtendedInteraction',
    'ExtendedFlywheelABM',
    'PolicyParams',
    'UserProfile',
    'Interaction',
    'RecordType',
    'License',
    'Attribution',
    'WorkflowState',
    'AgentType',
    'JurisdictionType',
]

