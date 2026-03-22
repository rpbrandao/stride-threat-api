"""
app/models/stride.py
Pydantic v2 models for STRIDE threat analysis request/response.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────

class StrideCategory(str, Enum):
    SPOOFING             = "Spoofing"
    TAMPERING            = "Tampering"
    REPUDIATION          = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE    = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

    @property
    def letter(self) -> str:
        return self.value[0]

    @property
    def violated_property(self) -> str:
        mapping = {
            "Spoofing":               "Authenticity",
            "Tampering":              "Integrity",
            "Repudiation":            "Non-repudiation",
            "Information Disclosure": "Confidentiality",
            "Denial of Service":      "Availability",
            "Elevation of Privilege": "Authorization",
        }
        return mapping[self.value]


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class Likelihood(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


# ──────────────────────────────────────────────
# Threat model
# ──────────────────────────────────────────────

class Threat(BaseModel):
    id: str = Field(description="Threat identifier, e.g. T001")
    category: StrideCategory
    stride_letter: str = Field(description="Single STRIDE letter: S/T/R/I/D/E")
    title: str = Field(description="Short threat title")
    description: str = Field(description="Detailed threat description")
    affected_components: list[str] = Field(description="Architecture components involved")
    risk_level: RiskLevel
    likelihood: Likelihood
    impact: RiskLevel
    mitigations: list[str] = Field(description="Recommended mitigations")
    references: list[str] = Field(
        default_factory=list,
        description="OWASP / CWE / CVE references"
    )


# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

class ThreatSummary(BaseModel):
    total_threats: int
    by_category: dict[str, int] = Field(description="Count per STRIDE letter")
    by_risk_level: dict[str, int]


# ──────────────────────────────────────────────
# Full report
# ──────────────────────────────────────────────

class StrideReport(BaseModel):
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    architecture_summary: str = Field(description="What the model understood from the image")
    threats: list[Threat]
    summary: ThreatSummary
    recommendations: list[str] = Field(description="Top priority actions")

    @classmethod
    def build_summary(cls, threats: list[Threat]) -> ThreatSummary:
        by_cat: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        for t in threats:
            letter = t.stride_letter
            by_cat[letter] = by_cat.get(letter, 0) + 1
            by_risk[t.risk_level.value] = by_risk.get(t.risk_level.value, 0) + 1
        return ThreatSummary(
            total_threats=len(threats),
            by_category=by_cat,
            by_risk_level=by_risk,
        )


# ──────────────────────────────────────────────
# Request / error models
# ──────────────────────────────────────────────

class AnalysisRequest(BaseModel):
    context: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Additional context about the application",
    )


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    status_code: int
