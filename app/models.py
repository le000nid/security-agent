"""Domain models used by the scanner and report generator."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]
NormalizedCategory = Literal[
    "security_headers",
    "cors",
    "secrets",
    "code_execution",
    "unsafe_deserialization",
    "tls_configuration",
    "debug_configuration",
    "injection",
    "authentication",
    "authorization",
    "information_exposure",
    "other",
]
SEVERITY_ORDER: tuple[Severity, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown",
)
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}


class Finding(BaseModel):
    """Scanner-independent finding; raw records live only in scanner logs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str
    source: Literal["SAST", "DAST"]
    tool: str
    category: str = "uncategorized"
    normalized_category: NormalizedCategory | None = None
    severity: Severity = "unknown"
    confidence: Literal["low", "medium", "high", "unknown"] = "unknown"
    location: str = ""
    evidence: str = ""
    description: str = ""
    recommendation: str = "Review and verify this scanner finding."
    raw_output_ref: str


def finding_sort_key(finding: Finding) -> tuple[int, str, str, str, str, str]:
    """Return the canonical deterministic report order for a finding."""

    return (
        SEVERITY_RANK[finding.severity],
        finding.source,
        finding.tool.casefold(),
        finding.title.casefold(),
        finding.location.casefold(),
        finding.id,
    )
