"""Unique isolated run paths and atomic portable latest-run pointer."""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True)
class RunPaths:
    run_id: str
    root: Path

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @classmethod
    def create(cls, base: Path = Path("runs")) -> "RunPaths":
        run_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid4().hex[:12]
        )
        root = base / run_id
        root.mkdir(parents=True, exist_ok=False)
        paths = cls(run_id, root)
        paths.logs.mkdir()
        paths.reports.mkdir()
        pointer = base / f".latest-{run_id}.json"
        pointer.write_text(json.dumps({"run_id": run_id}), encoding="utf-8")
        pointer.replace(base / "latest.json")
        return paths


def show_latest(base: Path = Path("runs")) -> int:
    """Read only the portable pointer; never start scanners or an LLM client."""
    try:
        run_id = json.loads((base / "latest.json").read_text(encoding="utf-8"))[
            "run_id"
        ]
        if not isinstance(run_id, str) or not re.fullmatch(
            r"\d{8}T\d{6}Z-[a-f0-9]{12}", run_id
        ):
            raise ValueError("Invalid pointer")
        reports = base / run_id / "reports"
        if not reports.resolve().is_relative_to(base.resolve()):
            raise ValueError("Unsafe pointer")
        summary = json.loads((reports / "summary.json").read_text(encoding="utf-8"))
        status = summary.get("status", "unknown")
        if status not in {"completed", "completed_with_warnings", "failed", "running"}:
            status = "unknown"
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        print("No readable latest run summary. Inspect runs/ or complete a scan first.")
        return 6
    print(f"Latest run: {run_id}\nStatus: {status}\nReports directory: {reports}")
    for label, name in (
        ("Report", "report.md"),
        ("Summary", "summary.json"),
        ("Trace", "agent_trace.json"),
        ("AI brief", "ai_brief.json"),
    ):
        print(f"{label}: {reports / name}")
    return 0
