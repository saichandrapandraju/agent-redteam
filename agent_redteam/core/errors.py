class AgentRedTeamError(Exception):
    """Base exception for all agent-redteam errors."""


class AdapterError(AgentRedTeamError):
    """Raised when an agent adapter encounters an error."""


class TemplateError(AgentRedTeamError):
    """Raised when an attack template is invalid or cannot be loaded."""


class ScanError(AgentRedTeamError):
    """Raised when a scan fails to execute."""


class BudgetExhaustedError(ScanError):
    """Raised when the scan budget (time, cost, or attack count) is exhausted."""
