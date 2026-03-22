"""
app/services/analysis_service.py
Orchestrates image validation, Azure OpenAI call, and response building.
"""

import logging
from io import BytesIO

from fastapi import UploadFile, HTTPException

from app.config import settings
from app.models.stride import StrideReport, Threat, ThreatSummary, StrideCategory, RiskLevel, Likelihood
from app.services.azure_openai_service import azure_service

logger = logging.getLogger(__name__)

ALLOWED_MIME_TYPES = {
    "image/png":  "image/png",
    "image/jpeg": "image/jpeg",
    "image/jpg":  "image/jpeg",
    "image/webp": "image/webp",
    "image/gif":  "image/gif",
}


async def validate_image(file: UploadFile) -> tuple[bytes, str]:
    """
    Read and validate the uploaded image file.

    Returns:
        Tuple of (image_bytes, media_type).

    Raises:
        HTTPException 400 on invalid file.
        HTTPException 413 on oversized file.
    """
    content_type = (file.content_type or "").lower()
    media_type = ALLOWED_MIME_TYPES.get(content_type)

    if not media_type:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{content_type}'. "
                   f"Allowed: {list(ALLOWED_MIME_TYPES.keys())}",
        )

    image_bytes = await file.read()

    if len(image_bytes) > settings.max_image_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(image_bytes)//1024//1024}MB). "
                   f"Max: {settings.MAX_IMAGE_SIZE_MB}MB",
        )

    if len(image_bytes) < 100:
        raise HTTPException(status_code=400, detail="File appears to be empty.")

    return image_bytes, media_type


def _build_report_from_json(raw: dict) -> StrideReport:
    """
    Parse and validate the GPT-4 Vision JSON response into a StrideReport.
    Applies safe fallbacks for partially valid responses.
    """
    raw_threats = raw.get("threats", [])
    threats: list[Threat] = []

    for i, t in enumerate(raw_threats):
        try:
            threat = Threat(
                id=t.get("id", f"T{i+1:03d}"),
                category=StrideCategory(t.get("category", "Spoofing")),
                stride_letter=t.get("stride_letter", "S"),
                title=t.get("title", "Unnamed threat"),
                description=t.get("description", ""),
                affected_components=t.get("affected_components", []),
                risk_level=RiskLevel(t.get("risk_level", "MEDIUM")),
                likelihood=Likelihood(t.get("likelihood", "MEDIUM")),
                impact=RiskLevel(t.get("impact", "MEDIUM")),
                mitigations=t.get("mitigations", []),
                references=t.get("references", []),
            )
            threats.append(threat)
        except Exception as e:
            logger.warning(f"Skipping malformed threat [{i}]: {e}")

    summary = StrideReport.build_summary(threats)

    return StrideReport(
        architecture_summary=raw.get("architecture_summary", "Analysis complete."),
        threats=threats,
        summary=summary,
        recommendations=raw.get("recommendations", []),
    )


async def run_stride_analysis(
    file: UploadFile,
    context: str | None = None,
) -> StrideReport:
    """
    Full pipeline: validate → call Azure OpenAI → build report.

    Args:
        file: Uploaded architecture diagram.
        context: Optional user-provided description.

    Returns:
        StrideReport with all identified threats.
    """
    # 1. Validate image
    image_bytes, media_type = await validate_image(file)
    logger.info(f"Image validated: {len(image_bytes)//1024}KB, type={media_type}")

    # 2. Call Azure OpenAI
    try:
        raw_json = await azure_service.analyze_architecture(
            image_bytes=image_bytes,
            media_type=media_type,
            context=context,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # 3. Build typed report
    report = _build_report_from_json(raw_json)
    logger.info(
        f"Report built: {report.summary.total_threats} threats, "
        f"id={report.analysis_id}"
    )
    return report
