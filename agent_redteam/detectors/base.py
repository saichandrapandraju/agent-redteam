"""DetectorRegistry — manages available signal detectors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_redteam.core.enums import VulnClass
from agent_redteam.core.models import CanaryToken
from agent_redteam.detectors.exfiltration import ExfiltrationDetector
from agent_redteam.detectors.injection_success import InjectionSuccessDetector
from agent_redteam.detectors.scope_violation import ScopeViolationDetector
from agent_redteam.detectors.secret_access import SecretAccessDetector
from agent_redteam.detectors.tool_misuse import ToolMisuseDetector

if TYPE_CHECKING:
    from agent_redteam.core.protocols import SignalDetector


class DetectorRegistry:
    """Manages available signal detectors."""

    def __init__(self) -> None:
        self._detectors: list[SignalDetector] = []

    def register(self, detector: SignalDetector) -> DetectorRegistry:
        self._detectors.append(detector)
        return self

    def defaults(
        self,
        canary_tokens: list[CanaryToken] | None = None,
        allowed_domains: list[str] | None = None,
    ) -> DetectorRegistry:
        """Register all built-in Phase 1 detectors."""
        self.register(SecretAccessDetector(canary_tokens=canary_tokens))
        self.register(ExfiltrationDetector(canary_tokens=canary_tokens, allowed_domains=allowed_domains))
        self.register(InjectionSuccessDetector())
        self.register(ToolMisuseDetector())
        self.register(ScopeViolationDetector())
        return self

    def for_classes(self, classes: list[VulnClass]) -> list[SignalDetector]:
        """Return detectors relevant to the given vulnerability classes."""
        class_set = set(classes)
        return [d for d in self._detectors if class_set.intersection(d.targets)]

    @property
    def all_detectors(self) -> list[SignalDetector]:
        return list(self._detectors)
