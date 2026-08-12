class AuthZGuardError(Exception):
    """Base exception for safe, actionable command-line errors."""


class ConfigurationError(AuthZGuardError):
    """A scope or matrix document is incomplete or unsafe."""


class ScopeViolation(AuthZGuardError):
    """A check falls outside the operator-declared, permitted scope."""

