"""
app/services/azure_openai_service.py
Azure OpenAI GPT-4 Vision client service.
"""

import base64
import json
import logging
from io import BytesIO

from openai import AsyncAzureOpenAI
from openai import APIConnectionError, APIStatusError, RateLimitError

from app.config import settings
from app.prompts.stride_prompt import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)


class AzureOpenAIService:
    """Async wrapper around Azure OpenAI for STRIDE analysis."""

    def __init__(self):
        self._client: AsyncAzureOpenAI | None = None

    def _get_client(self) -> AsyncAzureOpenAI:
        if self._client is None:
            self._client = AsyncAzureOpenAI(
                azure_endpoint=settings.AZURE_OPENAI_ENDPOINT,
                api_key=settings.AZURE_OPENAI_API_KEY,
                api_version=settings.AZURE_OPENAI_API_VERSION,
            )
        return self._client

    # ──────────────────────────────────────────
    # Image encoding
    # ──────────────────────────────────────────

    @staticmethod
    def encode_image(image_bytes: bytes, media_type: str = "image/png") -> str:
        """Encode image bytes to base64 data URL for Vision API."""
        b64 = base64.b64encode(image_bytes).decode("utf-8")
        return f"data:{media_type};base64,{b64}"

    # ──────────────────────────────────────────
    # Core analysis
    # ──────────────────────────────────────────

    async def analyze_architecture(
        self,
        image_bytes: bytes,
        media_type: str = "image/png",
        context: str | None = None,
    ) -> dict:
        """
        Send architecture image to GPT-4 Vision for STRIDE analysis.

        Args:
            image_bytes: Raw image file bytes.
            media_type: MIME type of the image.
            context: Optional user-provided application context.

        Returns:
            Parsed JSON dict from model response.

        Raises:
            ValueError: If model returns invalid JSON.
            RuntimeError: On Azure API errors.
        """
        if not settings.azure_configured:
            raise RuntimeError(
                "Azure OpenAI is not configured. "
                "Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY in .env"
            )

        client = self._get_client()
        image_url = self.encode_image(image_bytes, media_type)
        user_prompt = build_user_prompt(context)

        logger.info(
            f"Sending image to Azure OpenAI "
            f"[deployment={settings.AZURE_OPENAI_DEPLOYMENT}, "
            f"image_size={len(image_bytes)//1024}KB]"
        )

        try:
            response = await client.chat.completions.create(
                model=settings.AZURE_OPENAI_DEPLOYMENT,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image_url",
                                "image_url": {"url": image_url, "detail": "high"},
                            },
                            {"type": "text", "text": user_prompt},
                        ],
                    },
                ],
                max_tokens=settings.MAX_TOKENS_RESPONSE,
                temperature=0.1,   # Low temperature for consistent structured output
                response_format={"type": "json_object"},
            )

            raw_content = response.choices[0].message.content
            logger.info(
                f"Azure OpenAI response received "
                f"[tokens={response.usage.total_tokens}, "
                f"finish={response.choices[0].finish_reason}]"
            )

            try:
                return json.loads(raw_content)
            except json.JSONDecodeError as e:
                logger.error(f"JSON parse error: {e}\nRaw: {raw_content[:500]}")
                raise ValueError(f"Model returned invalid JSON: {e}") from e

        except RateLimitError as e:
            logger.error(f"Rate limit exceeded: {e}")
            raise RuntimeError("Azure OpenAI rate limit exceeded. Try again later.") from e

        except APIStatusError as e:
            logger.error(f"Azure API error {e.status_code}: {e.message}")
            raise RuntimeError(f"Azure OpenAI API error: {e.message}") from e

        except APIConnectionError as e:
            logger.error(f"Connection error: {e}")
            raise RuntimeError("Could not connect to Azure OpenAI. Check your endpoint.") from e


# Singleton instance
azure_service = AzureOpenAIService()
