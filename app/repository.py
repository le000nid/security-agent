"""Read-only, contained access to persisted v0.3/v0.4 run artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated

from pydantic import Field

from app.models import SEVERITY_ORDER, Finding
from app.safe_logging import redact, redact_data

RUN_ID_PATTERN = r"^\d{8}T\d{6}Z-[a-f0-9]{12}$"
RunId = Annotated[str, Field(pattern=RUN_ID_PATTERN)]
REPORT_FILES = frozenset(
    {"report.md", "findings.json", "summary.json", "ai_brief.json", "agent_trace.json"}
)


class RunRepository:
    def __init__(self, base: Path = Path("runs")):
        self.base = base.resolve()

    def path(self, run_id: str, filename: str) -> Path:
        if not re.fullmatch(RUN_ID_PATTERN, run_id):
            raise ValueError("invalid_run_id")
        if filename not in REPORT_FILES:
            raise ValueError("invalid_report_file")
        run = self.base / run_id
        path = run / "reports" / filename
        # Disallow even in-base symlink aliases of another run.
        if any(p.is_symlink() for p in (run, run / "reports", path)):
            raise ValueError("run_not_found")
        resolved = path.resolve()
        if not resolved.is_relative_to(self.base) or not resolved.is_file():
            raise ValueError("run_not_found")
        return resolved

    def text(self, run_id: str, filename: str) -> str:
        try:
            path = self.path(run_id, filename)
            if path.stat().st_size > 16_000_000:
                raise ValueError("run_unreadable")
            content = path.read_text(encoding="utf-8")
            if filename.endswith(".json"):
                # Redact decoded values, never encoded JSON syntax.
                return json.dumps(redact_data(json.loads(content)), ensure_ascii=False)
            return redact(content)
        except (OSError, UnicodeError):
            raise ValueError("run_unreadable") from None

    def json(self, run_id: str, filename: str):
        try:
            return json.loads(self.text(run_id, filename))
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("run_unreadable") from None

    def summary(self, run_id: str) -> dict:
        data = self.json(run_id, "summary.json")
        if (
            not isinstance(data, dict)
            or data.get("run_id", run_id) != run_id
            or not isinstance(data.get("total"), int)
        ):
            raise ValueError("run_unreadable")
        return redact_data(
            {
                **data,
                "run_id": run_id,
                "benchmark_id": data.get("benchmark_id"),
                "benchmark_name": data.get("benchmark_name"),
            }
        )

    def list(self) -> list[dict]:
        if not self.base.is_dir():
            return []
        result = []
        for path in sorted(self.base.iterdir(), key=lambda p: p.name, reverse=True):
            if not re.fullmatch(RUN_ID_PATTERN, path.name):
                continue
            try:
                result.append(self.summary(path.name))
            except ValueError:
                continue
            if len(result) >= 500:
                break
        return result

    def latest(self) -> str:
        entries = self.list()
        if not entries:
            raise ValueError("run_not_found")
        return entries[0]["run_id"]

    def findings(
        self,
        run_id: str,
        *,
        severity: str | None = None,
        source: str | None = None,
        category: str | None = None,
    ) -> list[dict]:
        data = self.json(run_id, "findings.json")
        if not isinstance(data, list):
            raise ValueError("run_unreadable")
        try:
            findings = [Finding.model_validate(f).model_dump(mode="json") for f in data]
        except ValueError:
            raise ValueError("run_unreadable") from None
        return sorted(
            [
                f
                for f in findings
                if (not severity or f["severity"] == severity)
                and (not source or f["source"] == source)
                and (
                    not category
                    or (f.get("normalized_category") or f["category"]) == category
                )
            ],
            key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"]),
        )

    def detail(self, run_id: str) -> dict:
        data = self.summary(run_id)
        for key, filename in (
            ("ai_brief", "ai_brief.json"),
            ("trace", "agent_trace.json"),
        ):
            try:
                data[key] = self.json(run_id, filename)
            except ValueError:
                data[key] = None
        data["artifacts"] = sorted(REPORT_FILES)
        return data
