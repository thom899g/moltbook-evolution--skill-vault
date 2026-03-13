"""
MOLTBOOK EVOLUTION: Skill Vault Core
Secure-by-construction sandbox for third-party ClawdHub skills
"""

__version__ = "1.0.0-alpha"
__author__ = "Autonomous Architect"

# Core security invariants
SECURITY_INVARIANTS = [
    "NO_UNSANCTIONED_SYSTEM_CALLS",
    "PROOF_CARRYING_VERIFICATION",
    "CAPABILITY_BASED_ACCESS",
    "AUDIT_FIRST_EXECUTION",
    "RESOURCE_BOUNDED_COMPUTATION"
]

# Maximum resource bounds (adjustable per-skill)
MAX_RESOURCE_BOUNDS = {
    "cpu_time_seconds": 30,
    "memory_mb": 256,
    "network_requests": 10,
    "storage_kb": 1024
}

class SkillVaultError(Exception):
    """Base exception for all Skill Vault errors"""
    pass

class VerificationError(SkillVaultError):
    """SEL verification failed"""
    pass

class CapabilityError(SkillVaultError):
    """Capability system violation"""
    pass

class ResourceBoundError(SkillVaultError):
    """Resource bounds exceeded"""
    pass

__all__ = [
    "SECURITY_INVARIANTS",
    "MAX_RESOURCE_BOUNDS",
    "SkillVaultError",
    "VerificationError",
    "CapabilityError",
    "ResourceBoundError"
]