"""Failure-isolated enrichment; failed units keep the original scanner objects."""

import logging
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.llm import Enrichment, OpenAICompatibleClient
from app.llm_output import LLMError
from app.models import Finding
from app.safe_logging import redact


class FindingFailure(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: str
    error_code: str


class EnrichmentStats(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    requested: int = 0
    completed: int = 0
    failed: int = 0
    retried: int = 0
    failures: list[FindingFailure] = Field(default_factory=list)


@dataclass
class EnrichmentResult:
    findings: list[Finding]
    rationales: dict[str, str]
    stats: EnrichmentStats


def enrich_independently(
    findings: list[Finding],
    client: OpenAICompatibleClient,
    *,
    include_evidence: bool = False,
    batch_size: int = 1,
) -> EnrichmentResult:
    """A unit is one finding by default, or one atomic experimental batch.

    Only truncation gets one content retry. HTTP timeout/429/5xx retries remain
    bounded in the transport. No input/response bodies enter failure metadata.
    """
    if not 1 <= batch_size <= 20 or len({f.id for f in findings}) != len(findings):
        raise LLMError("enrichment", "identity_mismatch")
    stats = EnrichmentStats(requested=len(findings))
    enriched, rationales = [], {}
    for start in range(0, len(findings), batch_size):
        batch = findings[start : start + batch_size]
        for attempt in range(2):
            try:
                kwargs = {"include_evidence": include_evidence}
                if attempt:
                    kwargs["retry"] = True
                results = (
                    client.enrich_batch(batch, **kwargs)
                    if batch_size > 1
                    else {batch[0].id: client.enrich(batch[0], **kwargs)}
                )
                if set(results) != {f.id for f in batch}:
                    raise LLMError("enrichment", "identity_mismatch")
                # Validate the entire unit before committing any updates.
                results = {
                    id_: Enrichment.model_validate(value)
                    for id_, value in results.items()
                }
                for finding in batch:
                    result = results[finding.id]
                    enriched.append(
                        finding.model_copy(
                            update={
                                field: redact(getattr(result, field))
                                if field in ("description", "recommendation")
                                else getattr(result, field)
                                for field in (
                                    "description",
                                    "normalized_category",
                                    "severity",
                                    "recommendation",
                                )
                            }
                        )
                    )
                    rationales[finding.id] = redact(result.reasoning_short)
                stats.completed += len(batch)
                break
            except Exception as exc:
                code = (
                    exc.code
                    if isinstance(exc, LLMError)
                    else "enrichment_schema_validation_error"
                    if isinstance(exc, ValidationError)
                    else "enrichment_unavailable"
                )
                if code == "enrichment_response_truncated" and attempt == 0:
                    stats.retried += len(batch)
                    continue
                stats.failed += len(batch)
                stats.failures.extend(
                    FindingFailure(finding_id=f.id, error_code=code) for f in batch
                )
                enriched.extend(batch)
                logging.getLogger("security_agent").warning(
                    "%s: retained %d scanner finding(s)", code, len(batch)
                )
                break
    assert len(enriched) == len(findings)
    return EnrichmentResult(enriched, rationales, stats)
