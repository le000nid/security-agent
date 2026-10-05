"""Conservative JSON decoding and fixed, non-sensitive LLM diagnostics."""

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

Model = TypeVar("Model", bound=BaseModel)


class LLMError(ValueError):
    """Only application-authored codes/messages; never attach provider text."""

    def __init__(self, role: str, kind: str):
        self.code = f"{role}_{kind}"
        self.message = f"{role.capitalize()} failed: {kind.replace('_', ' ')}."
        self.validation_issues: list[dict[str, str]] = []
        super().__init__(self.message)


class ChatResponseTruncated(LLMError):
    """Ephemeral answer content, never exception text/logs or provider reasoning."""

    def __init__(self, content: str = ""):
        from app.safe_logging import redact

        super().__init__("chat_analysis", "response_truncated")
        self.partial_content = redact(content)[:32768]


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def extract_json(content: str, role: str) -> str:
    """Accept exactly one object, optionally fenced or surrounded by plain prose.

    Never salvage a nested object from a broken outer object. Braces in prose,
    arrays, multiple objects/blocks and duplicate keys are deliberately rejected.
    """
    if not isinstance(content, str) or not content.strip():
        raise LLMError(role, "empty_content")
    text = content.strip()
    if "```" in text:
        pattern = r"```(?:json)?\s*\n?(.*?)\s*```"
        if role == "brief":
            # One fenced object surrounded by plain prose is unambiguous. Never
            # extract a nested object, multiple fences or brace-containing prose.
            pattern = r"[^`{}\[\]]*```(?:json)?\s*\n?(.*?)\s*```[^`{}\[\]]*"
        match = re.fullmatch(pattern, text, re.DOTALL)
        if not match:
            raise LLMError(role, "json_decode_error")
        text = match[1].strip()
    start, end = text.find("{"), text.rfind("}")
    if (
        start < 0
        or end < start
        or any(c in text[:start] + text[end + 1 :] for c in "[]{}")
    ):
        raise LLMError(role, "json_decode_error")
    candidate = text[start : end + 1]
    try:
        decoded = json.loads(candidate, object_pairs_hook=_unique_object)
        if not isinstance(decoded, dict):
            raise ValueError("Expected object")
    except (ValueError, RecursionError):
        raise LLMError(role, "json_decode_error") from None
    return candidate


def validate_output(content: str, model: type[Model], role: str) -> Model:
    candidate = extract_json(content, role)
    try:
        return model.model_validate_json(candidate)
    except ValidationError as exc:
        # Only inspect known schema locations. Never render input, ctx or unknown keys.
        errors = exc.errors(include_input=False, include_context=False)
        if (
            role == "chat_analysis"
            and errors
            and all(
                e["type"] in {"string_too_long", "too_long", "chat_output_too_long"}
                for e in errors
            )
        ):
            raise ChatResponseTruncated(candidate) from None
        kind = "schema_validation_error"
        if role == "planner" and any(
            e["loc"] == ("action",) and e["type"] == "enum" for e in errors
        ):
            kind = "unknown_action"
        elif role == "enrichment":
            if any("normalized_category" in e["loc"] for e in errors):
                kind = "invalid_category"
            elif any(
                e["type"] == "extra_forbidden"
                and e["loc"][-1]
                in {
                    "id",
                    "source",
                    "tool",
                    "category",
                    "confidence",
                    "location",
                    "title",
                    "evidence",
                    "raw_output_ref",
                }
                for e in errors
            ):
                kind = "identity_mismatch"
        error = LLMError(role, kind)
        if role == "brief":
            error.validation_issues = safe_validation_issues(errors, model)
        raise error from None


def safe_validation_issues(
    errors: list[dict], model: type[BaseModel]
) -> list[dict[str, str]]:
    """Only schema-owned field names/types; never unknown key names, inputs or ctx."""
    fields = set()

    def collect(schema):
        if isinstance(schema, dict):
            fields.update(schema.get("properties", {}))
            for value in schema.values():
                collect(value)
        elif isinstance(schema, list):
            for value in schema:
                collect(value)

    collect(model.model_json_schema())
    types = {
        "string_too_long",
        "string_too_short",
        "too_long",
        "too_short",
        "missing",
        "extra_forbidden",
        "string_type",
        "list_type",
        "model_type",
        "value_error",
    }
    return [
        {
            "field": ".".join(
                str(p) if isinstance(p, int) else p if p in fields else "<unknown>"
                for p in e["loc"]
            )
            or "<root>",
            "type": e["type"] if e["type"] in types else "validation_error",
        }
        for e in errors[:10]
    ]
