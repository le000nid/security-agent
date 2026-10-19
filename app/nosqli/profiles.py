"""Reviewed API contracts. Profiles are local configuration, never LLM input."""

import re
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.resources import config_directory

Name = Annotated[str, Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$")]
ProfileId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
KeyPath = Annotated[list[Name], Field(min_length=1, max_length=8)]


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: ProfileId
    method: Literal["POST", "GET"] = "POST"
    path: str = Field(max_length=256)
    field_path: KeyPath
    query_parameter: Name = "filter"
    baseline: str = Field(min_length=1, max_length=80)
    records_path: KeyPath
    id_path: KeyPath
    value_path: KeyPath

    @model_validator(mode="after")
    def validate_contract(self):
        if not re.fullmatch(r"/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+", self.path):
            raise ValueError("profile_path_must_be_local")
        if any(
            key in {"__proto__", "constructor", "prototype"}
            for path in (
                self.field_path,
                self.records_path,
                self.id_path,
                self.value_path,
            )
            for key in path
        ):
            raise ValueError("reserved_profile_key")
        return self


def load_profiles(selected: list[str]) -> list[Profile]:
    if not selected or len(selected) > 8 or len(set(selected)) != len(selected):
        raise ValueError("invalid_nosqli_profile_selection")
    data = yaml.safe_load(
        (config_directory() / "nosqli-profiles.yaml").read_text(encoding="utf-8")
    )
    if not isinstance(data, list) or len(data) > 64:
        raise ValueError("invalid_nosqli_profile_registry")
    profiles = [Profile.model_validate(item) for item in data]
    by_id = {p.id: p for p in profiles}
    if len(by_id) != len(profiles) or any(key not in by_id for key in selected):
        raise ValueError("unknown_or_duplicate_nosqli_profile")
    return [by_id[key] for key in selected]
