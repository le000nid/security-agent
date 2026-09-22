"""OpenAI-compatible, validated enrichment with no scanner or subprocess access."""

import json
import os
import time
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models import Finding, NormalizedCategory, Severity

MAX_RETRIES = 2
SYSTEM_PROMPT = (
    "You are a defensive assistant analyzing one finding already produced by a trusted "
    "SAST or DAST scanner. Analyze only the supplied finding. Never invent, add, or "
    "discover another vulnerability. Separate observed facts, possible security "
    "implications, and hypothetical conditions not observed by the scanner. Never "
    "present a hypothetical exploit prerequisite as observed. Do not claim that a "
    "vulnerability becomes exploitable merely because another header or setting might "
    "exist unless that condition was actually observed. For CORS, Access-Control-Allow-"
    "Origin: * permits cross-origin reading only of resources accessible without "
    "credentials and can expose public or otherwise unauthenticated responses. Modern "
    "browsers reject wildcard Access-Control-Allow-Origin for credentialed requests; "
    "credentialed CORS requires a specific allowed origin. Never claim authenticated "
    "cross-origin data theft unless the evidence shows an actually unsafe credentialed "
    "CORS configuration. Never generate commands intended for execution, request "
    "external scanning, call tools, or act as an autonomous pentester. Keep description "
    "and recommendation to 2-4 short sentences, preferably no more than 90 words each. "
    "Keep reasoning_short to 1-2 sentences, preferably no more than 50 words. Use only "
    "the supplied metadata and return JSON only. Return exactly this schema: "
)


class Enrichment(BaseModel):
    """The only fields an LLM is allowed to produce for an existing finding."""

    model_config = ConfigDict(extra="forbid", strict=True)

    description: str = Field(min_length=1, max_length=800)
    normalized_category: NormalizedCategory | None = None
    severity: Severity
    recommendation: str = Field(min_length=1, max_length=800)
    reasoning_short: str = Field(min_length=1, max_length=400)

    @field_validator("description", "recommendation", "reasoning_short")
    @classmethod
    def non_empty_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("LLM enrichment fields must not be blank")
        return value

    @model_validator(mode="after")
    def reject_incorrect_wildcard_cors_claim(self) -> "Enrichment":
        """Reject the specific credentialed-wildcard overclaim the prompt forbids."""

        text = " ".join(
            (self.description, self.recommendation, self.reasoning_short)
        ).casefold()
        false_claims = (
            "allows credentialed cross-origin reads",
            "enables credentialed cross-origin reads",
            "permits credentialed cross-origin reads",
            "allows credentialed reads",
            "enables credentialed reads",
            "permits credentialed reads",
        )
        wildcard_context = (
            "access-control-allow-origin: *" in text or "* + credentials" in text
        )
        if wildcard_context and any(claim in text for claim in false_claims):
            raise ValueError(
                "Wildcard Access-Control-Allow-Origin must not be described as enabling "
                "credentialed cross-origin reads"
            )
        return self


class LLMFindingInput(BaseModel):
    """Privacy-minimized projection sent to the enrichment provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str
    source: str
    tool: str
    category: str
    severity: Severity
    confidence: str
    location: str
    description: str
    evidence: str | None = None

    @classmethod
    def from_finding(
        cls, finding: Finding, *, include_evidence: bool = False
    ) -> "LLMFindingInput":
        location = finding.location.replace("\\", "/")
        if finding.source == "SAST" and ":" in location:
            file_name, line = location.rsplit(":", 1)
            location = f"{file_name.rsplit('/', 1)[-1]}:{line}"
        return cls(
            id=finding.id,
            title=finding.title,
            source=finding.source,
            tool=finding.tool,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            location=location,
            description=finding.description,
            evidence=finding.evidence
            if include_evidence and finding.evidence
            else None,
        )


class LLMUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def add_response(self, usage: object) -> None:
        self.requests += 1
        if not isinstance(usage, dict):
            return
        for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(field, 0)
            if isinstance(value, int) and value >= 0:
                setattr(self, field, getattr(self, field) + value)


def _validate_base_url(value: str) -> str:
    candidate = value.strip().rstrip("/")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid LLM_BASE_URL: {exc}") from exc
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("LLM_BASE_URL must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "LLM_BASE_URL must not contain credentials, query, or fragment"
        )
    if parsed.path.rstrip("/").endswith(("/chat/completions", "/models")):
        raise ValueError("LLM_BASE_URL must be the API base, not an endpoint URL")
    netloc = parsed.hostname.lower()
    if port is not None:
        netloc += f":{port}"
    return urlunsplit(("https", netloc, parsed.path.rstrip("/"), "", ""))


class OpenAICompatibleClient:
    """A minimal chat-completions client used only for finding enrichment."""

    def __init__(self, *, sleeper: Callable[[float], None] = time.sleep) -> None:
        if os.getenv("LLM_PROVIDER", "").lower() != "openai_compatible":
            raise ValueError("Set LLM_PROVIDER=openai_compatible or use --no-llm")
        self.provider = "openai_compatible"
        self.base_url = _validate_base_url(os.getenv("LLM_BASE_URL", ""))
        self.model = os.getenv("LLM_MODEL", "").strip()
        self._key = os.getenv("LLM_API_KEY", "")
        if not self.model or not self._key:
            raise ValueError("LLM_MODEL and LLM_API_KEY are required unless --no-llm")
        self.models_url = f"{self.base_url}/models"
        self.chat_url = f"{self.base_url}/chat/completions"
        self._sleeper = sleeper
        self._model_available = False
        self.available_model_ids: tuple[str, ...] = ()
        self.usage = LLMUsage()

    @property
    def model_available(self) -> bool:
        return self._model_available

    def public_metadata(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "model_available": self.model_available,
        }

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key}"}

    def _request(
        self, method: str, url: str, *, payload: dict[str, object] | None = None
    ) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                with httpx.Client(
                    timeout=30, trust_env=False, follow_redirects=False
                ) as client:
                    response = client.request(
                        method, url, headers=self._headers(), json=payload
                    )
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt < MAX_RETRIES:
                    self._sleeper(0.1 * (2**attempt))
                    continue
                raise ValueError("LLM request timed out after retries") from exc
            except httpx.HTTPError as exc:
                raise ValueError("LLM transport failed") from exc

            if response.status_code == 429 or response.status_code >= 500:
                if attempt < MAX_RETRIES:
                    self._sleeper(0.1 * (2**attempt))
                    continue
            return response
        raise ValueError("LLM request failed") from last_error

    @staticmethod
    def _raise_status(response: httpx.Response, *, discovery: bool) -> None:
        status = response.status_code
        if 200 <= status < 300:
            return
        messages = {
            400: "invalid request",
            401: "authentication failed",
            403: "access denied",
            404: "wrong model-discovery endpoint"
            if discovery
            else "wrong chat-completions endpoint",
            429: "rate limited after retries",
        }
        if status >= 500:
            detail = "gateway/backend failure after retries"
        else:
            detail = messages.get(status, f"HTTP {status}")
        context = "Model discovery" if discovery else "LLM completion"
        raise ValueError(f"{context} failed: {detail}")

    def ensure_model_available(self) -> None:
        """Validate the configured exact model ID once for this client."""

        if self._model_available:
            return
        response = self._request("GET", self.models_url)
        self._raise_status(response, discovery=True)
        try:
            payload = response.json()
            data = payload["data"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(
                "Invalid OpenAI-compatible model discovery response"
            ) from exc
        if not isinstance(data, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("id"), str)
            for item in data
        ):
            raise ValueError("Invalid OpenAI-compatible model discovery response")
        self.available_model_ids = tuple(sorted({item["id"] for item in data}))
        if self.model not in self.available_model_ids:
            preview = ", ".join(self.available_model_ids[:10]) or "none"
            raise ValueError(
                f"Configured model unavailable: {self.model}. Available model IDs: {preview}"
            )
        self._model_available = True

    def enrich(self, finding: Finding, *, include_evidence: bool = False) -> Enrichment:
        self.ensure_model_available()
        system = SYSTEM_PROMPT + json.dumps(Enrichment.model_json_schema())
        request_body: dict[str, object] = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "max_tokens": 600,
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": LLMFindingInput.from_finding(
                        finding, include_evidence=include_evidence
                    ).model_dump_json(exclude_none=True),
                },
            ],
        }
        response = self._request("POST", self.chat_url, payload=request_body)
        self._raise_status(response, discovery=False)
        try:
            payload = response.json()
            choice = payload["choices"][0]
            message = choice["message"]
            content = message["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ValueError("Invalid OpenAI-compatible chat response") from exc
        self.usage.add_response(payload.get("usage"))
        if choice.get("finish_reason") != "stop" or message.get("tool_calls"):
            raise ValueError("Incomplete response or unexpected tool call")
        try:
            return Enrichment.model_validate_json(content)
        except (ValueError, TypeError) as exc:
            raise ValueError("LLM enrichment failed schema validation") from exc


def enrich_findings(
    findings: list[Finding],
    client: OpenAICompatibleClient,
    *,
    include_evidence: bool = False,
) -> tuple[list[Finding], dict[str, str]]:
    """Enrich fields while preserving count and every identity-bearing field."""

    client.ensure_model_available()
    enriched: list[Finding] = []
    rationales: dict[str, str] = {}
    for finding in findings:
        result = Enrichment.model_validate(
            client.enrich(finding, include_evidence=include_evidence)
        )
        enriched.append(
            finding.model_copy(
                update={
                    "description": result.description,
                    "normalized_category": result.normalized_category,
                    "severity": result.severity,
                    "recommendation": result.recommendation,
                }
            )
        )
        rationales[finding.id] = result.reasoning_short
    if len(enriched) != len(findings):
        raise ValueError("LLM enrichment changed the finding count")
    return enriched, rationales


# Backward-compatible import for integrations written against v0.2.1.
LLMClient = OpenAICompatibleClient
