"""Tests for core enums."""

from agent_redteam.core.enums import (
    EventType,
    ScanProfile,
    TrustBoundary,
    VulnClass,
)


class TestVulnClass:
    def test_all_17_classes(self):
        assert len(VulnClass) == 17

    def test_values(self):
        assert VulnClass.V1_INDIRECT_INJECTION == "V1"
        assert VulnClass.V7_DATA_EXFILTRATION == "V7"

    def test_from_string(self):
        assert VulnClass("V1") == VulnClass.V1_INDIRECT_INJECTION


class TestTrustBoundary:
    def test_all_7_boundaries(self):
        assert len(TrustBoundary) == 7


class TestEventType:
    def test_dot_notation(self):
        assert EventType.TOOL_CALL == "tool.call"
        assert EventType.FILE_READ == "file.read"


class TestScanProfile:
    def test_profiles(self):
        assert ScanProfile.QUICK.value == "quick"
        assert ScanProfile.DEEP_RED_TEAM.value == "deep_red_team"
