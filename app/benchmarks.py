"""Application-owned benchmark registry. Never populated from HTTP or LLM input."""

import re
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.resources import config_directory

BenchmarkId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
Mode = Literal["sast", "dast", "full"]


class Benchmark(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: BenchmarkId
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1000)
    capabilities: list[Literal["sast", "dast"]] = Field(min_length=1, max_length=2)
    source_path: str | None = None
    target_url: str | None = None
    docker_service: BenchmarkId | None = None
    expected_findings: str | None = None
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True

    @model_validator(mode="after")
    def safe_config(self):
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("duplicate_capability")
        if ("sast" in self.capabilities) != bool(self.source_path):
            raise ValueError("benchmark_source_required")
        if ("dast" in self.capabilities) != bool(self.target_url):
            raise ValueError("benchmark_target_required")
        if self.source_path:
            path = PurePosixPath(self.source_path)
            if (
                not self.source_path.startswith("/targets/")
                or any(
                    not re.fullmatch(r"[a-zA-Z0-9_-]+", part) for part in path.parts[2:]
                )
                or len(path.parts) < 3
                or str(path) != self.source_path
            ):
                raise ValueError("invalid_benchmark_source")
        if self.target_url:
            from app.validation import _validate_target_url

            hosts = {"localhost", "127.0.0.1"}
            if self.docker_service:
                # Single-label service names only; never dotted domains/IPs.
                if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", self.docker_service):
                    raise ValueError("invalid_docker_service")
                hosts.add(self.docker_service)
            _validate_target_url(self.target_url, hosts)
        if self.expected_findings and not re.fullmatch(
            r"[a-z0-9][a-z0-9-]*\.json", self.expected_findings
        ):
            raise ValueError("invalid_expected_findings")
        return self

    def resolve_mode(self, mode: Mode | None = None) -> Mode:
        selected = mode or (
            "full" if len(self.capabilities) == 2 else self.capabilities[0]
        )
        required = {"sast", "dast"} if selected == "full" else {selected}
        if not required.issubset(self.capabilities):
            raise ValueError("benchmark_mode_not_supported")
        return selected

    def local_source(self) -> str | None:
        if self.source_path is None:
            return None
        root = (
            Path("/targets")
            if Path("/targets").is_dir()
            else Path(__file__).resolve().parent.parent / "targets"
        )
        path = root.joinpath(*PurePosixPath(self.source_path).parts[2:]).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError("invalid_benchmark_source")
        return str(path)


class BenchmarkRegistry:
    def __init__(self, entries: list[Benchmark]):
        if len({b.id for b in entries}) != len(entries):
            raise ValueError("duplicate_benchmark_id")
        self._entries = {b.id: b for b in entries}

    @classmethod
    def load(cls) -> "BenchmarkRegistry":
        try:
            data = yaml.safe_load(
                (config_directory() / "benchmarks.yaml").read_text(encoding="utf-8")
            )
        except yaml.YAMLError:
            raise ValueError("invalid_registry") from None
        if not isinstance(data, list):
            raise ValueError("invalid_registry")
        return cls([Benchmark.model_validate(item) for item in data])

    def list(self) -> list[Benchmark]:
        return [b for b in self._entries.values() if b.enabled]

    def get(self, benchmark_id: str) -> Benchmark:
        entry = self._entries.get(benchmark_id)
        if entry is None or not entry.enabled:
            raise ValueError("benchmark_not_found")
        return entry

    def trusted_hosts(self) -> frozenset[str]:
        return frozenset(
            urlsplit(b.target_url).hostname for b in self.list() if b.target_url
        )
