"""
tests/test_analysis.py
Unit and integration tests for the STRIDE analysis pipeline.
"""

import json
from io import BytesIO
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.main import app
from app.models.stride import RiskLevel, StrideCategory, Threat, Likelihood
from app.services.analysis_service import _build_report_from_json
from app.prompts.stride_prompt import build_user_prompt

client = TestClient(app)

# ── Fixtures ──────────────────────────────────

MOCK_AZURE_RESPONSE = {
    "architecture_summary": "A three-tier web application with React frontend, Node.js API, and PostgreSQL database behind an API Gateway.",
    "threats": [
        {
            "id": "T001",
            "category": "Spoofing",
            "stride_letter": "S",
            "title": "JWT token forgery at API Gateway",
            "description": "Attacker could forge JWT tokens if weak signing algorithm is used.",
            "affected_components": ["API Gateway", "Auth Service"],
            "risk_level": "HIGH",
            "likelihood": "MEDIUM",
            "impact": "HIGH",
            "mitigations": ["Use RS256 signing", "Short token expiry"],
            "references": ["OWASP A07:2021", "CWE-287"],
        },
        {
            "id": "T002",
            "category": "Information Disclosure",
            "stride_letter": "I",
            "title": "Unencrypted database traffic",
            "description": "Database connection may not enforce TLS.",
            "affected_components": ["API Server", "PostgreSQL"],
            "risk_level": "MEDIUM",
            "likelihood": "MEDIUM",
            "impact": "MEDIUM",
            "mitigations": ["Enforce ssl=require on DB connections"],
            "references": ["CWE-319"],
        },
    ],
    "recommendations": [
        "Implement mTLS between all internal services",
        "Enable audit logging on the database",
    ],
}

# ── Unit Tests: Report Builder ─────────────────

class TestReportBuilder:
    def test_builds_report_from_valid_json(self):
        report = _build_report_from_json(MOCK_AZURE_RESPONSE)
        assert report.summary.total_threats == 2
        assert report.threats[0].category == StrideCategory.SPOOFING
        assert report.threats[0].risk_level == RiskLevel.HIGH
        assert len(report.recommendations) == 2

    def test_summary_counts_by_category(self):
        report = _build_report_from_json(MOCK_AZURE_RESPONSE)
        assert report.summary.by_category["S"] == 1
        assert report.summary.by_category["I"] == 1

    def test_summary_counts_by_risk(self):
        report = _build_report_from_json(MOCK_AZURE_RESPONSE)
        assert report.summary.by_risk_level["HIGH"] == 1
        assert report.summary.by_risk_level["MEDIUM"] == 1

    def test_handles_empty_threats(self):
        report = _build_report_from_json({"threats": [], "architecture_summary": "Empty"})
        assert report.summary.total_threats == 0

    def test_skips_malformed_threat(self):
        data = {
            "architecture_summary": "Test",
            "threats": [
                {"id": "T001", "category": "INVALID_CATEGORY"},  # malformed
                MOCK_AZURE_RESPONSE["threats"][0],               # valid
            ],
            "recommendations": [],
        }
        report = _build_report_from_json(data)
        assert report.summary.total_threats == 1  # only valid one

    def test_report_has_uuid_and_timestamp(self):
        report = _build_report_from_json(MOCK_AZURE_RESPONSE)
        assert len(report.analysis_id) == 36  # UUID format
        assert report.timestamp is not None


# ── Unit Tests: Prompt Engineering ────────────

class TestPromptEngineering:
    def test_prompt_without_context(self):
        prompt = build_user_prompt(context=None)
        assert "STRIDE" in prompt
        assert "architecture_summary" in prompt
        assert "threats" in prompt

    def test_prompt_injects_context(self):
        ctx = "E-commerce with OAuth2 and Redis cache"
        prompt = build_user_prompt(context=ctx)
        assert ctx in prompt

    def test_prompt_contains_all_stride_letters(self):
        prompt = build_user_prompt()
        for letter in ["Spoofing", "Tampering", "Repudiation",
                       "Information Disclosure", "Denial of Service",
                       "Elevation of Privilege"]:
            assert letter in prompt


# ── Unit Tests: Models ─────────────────────────

class TestStrideModels:
    def test_threat_category_letter(self):
        assert StrideCategory.SPOOFING.letter == "S"
        assert StrideCategory.TAMPERING.letter == "T"
        assert StrideCategory.DENIAL_OF_SERVICE.letter == "D"

    def test_threat_violated_property(self):
        assert StrideCategory.SPOOFING.violated_property == "Authenticity"
        assert StrideCategory.INFORMATION_DISCLOSURE.violated_property == "Confidentiality"
        assert StrideCategory.DENIAL_OF_SERVICE.violated_property == "Availability"


# ── Integration Tests: API Endpoints ──────────

class TestHealthEndpoint:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestCategoriesEndpoint:
    def test_returns_six_categories(self):
        response = client.get("/api/v1/categories")
        assert response.status_code == 200
        data = response.json()
        assert len(data["categories"]) == 6

    def test_all_stride_letters_present(self):
        response = client.get("/api/v1/categories")
        letters = {c["letter"] for c in response.json()["categories"]}
        assert letters == {"S", "T", "R", "I", "D", "E"}


class TestAnalyzeEndpoint:
    def _make_png_bytes(self) -> bytes:
        """Return minimal valid PNG bytes."""
        import struct, zlib
        def chunk(name, data):
            c = name + data
            return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        idat = chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
        iend = chunk(b"IEND", b"")
        return sig + ihdr + idat + iend

    def test_returns_422_for_missing_image(self):
        response = client.post("/api/v1/analyze")
        assert response.status_code == 422

    def test_returns_400_for_non_image(self):
        response = client.post(
            "/api/v1/analyze",
            files={"image": ("test.txt", b"not an image", "text/plain")},
        )
        assert response.status_code == 400

    @patch("app.services.analysis_service.azure_service.analyze_architecture",
           new_callable=AsyncMock)
    def test_successful_analysis(self, mock_azure):
        mock_azure.return_value = MOCK_AZURE_RESPONSE
        png = self._make_png_bytes()
        response = client.post(
            "/api/v1/analyze",
            files={"image": ("arch.png", png, "image/png")},
            data={"context": "Test app"},
        )
        assert response.status_code == 200
        body = response.json()
        assert "threats" in body
        assert "summary" in body
        assert body["summary"]["total_threats"] == 2

    @patch("app.services.analysis_service.azure_service.analyze_architecture",
           new_callable=AsyncMock)
    def test_azure_error_returns_502(self, mock_azure):
        mock_azure.side_effect = RuntimeError("Azure unreachable")
        png = self._make_png_bytes()
        response = client.post(
            "/api/v1/analyze",
            files={"image": ("arch.png", png, "image/png")},
        )
        assert response.status_code == 502
