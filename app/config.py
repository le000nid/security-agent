"""Typed runtime settings. Secrets are excluded from every model serialization."""

import os
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class ReportTone(StrEnum):
    PROFESSIONAL = "professional"
    CONCISE = "concise"
    FUNNY = "funny"


class ReportLanguage(StrEnum):
    RU = "ru"
    EN = "en"


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    llm_provider: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    llm_api_key: SecretStr = Field(default=SecretStr(""), exclude=True, repr=False)
    agent_max_steps: int = Field(default=8, ge=1, le=100)
    agent_max_planner_calls: int = Field(default=8, ge=1, le=100)
    llm_planner_max_tokens: int = Field(default=320, ge=256, le=2048)
    llm_planner_retry_max_tokens: int = Field(default=512, ge=256, le=2048)
    llm_enrichment_batch_size: int = Field(default=1, ge=1, le=20)
    llm_enrichment_max_tokens: int = Field(default=1200, ge=256, le=8192)
    llm_enrichment_retry_max_tokens: int = Field(default=2200, ge=256, le=8192)
    llm_brief_enabled: bool = True
    llm_brief_max_tokens: int = Field(default=2000, ge=256, le=8192)
    llm_brief_retry_max_tokens: int = Field(default=3200, ge=256, le=8192)
    llm_chat_max_tokens: int = Field(default=2400, ge=256, le=8192)
    llm_chat_retry_max_tokens: int = Field(default=3600, ge=256, le=8192)
    llm_report_tone: ReportTone = ReportTone.PROFESSIONAL
    llm_report_language: ReportLanguage = ReportLanguage.RU

    @model_validator(mode="after")
    def retry_budgets(self) -> "Settings":
        if (
            self.llm_enrichment_retry_max_tokens <= self.llm_enrichment_max_tokens
            or self.llm_brief_retry_max_tokens <= self.llm_brief_max_tokens
            or self.llm_planner_retry_max_tokens <= self.llm_planner_max_tokens
            or self.llm_chat_retry_max_tokens <= self.llm_chat_max_tokens
        ):
            raise ValueError("Retry token budgets must exceed normal budgets")
        return self

    @classmethod
    def from_env(cls) -> "Settings":
        values = {
            name: os.environ[name.upper()]
            for name in cls.model_fields
            if name.upper() in os.environ
        }
        try:
            return cls.model_validate(values)
        except ValueError:
            raise ValueError(
                "Invalid runtime settings; check limits, token budgets, tone and language"
            ) from None
