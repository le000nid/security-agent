"""Validate a reviewed JS/TS corpus, exact Semgrep locations and common reports."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.repository import RunRepository
from app.resources import config_directory
from benchmark.verify_nosqli_sast import MARKER
from benchmark.verify_nosqli_sast import verify as verify_locations

FUNCTION = re.compile(r"export function ([a-zA-Z_][a-zA-Z0-9_]*)\(")


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,100}$")
    file: str
    function: str = Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]*$")
    rule: str = Field(pattern=r"^javascript-nosqli-[a-z-]+$")
    expected: bool

    @model_validator(mode="after")
    def local_file(self):
        path = PurePosixPath(self.file)
        if (
            len(path.parts) != 2
            or path.parts[0] not in {"javascript", "typescript"}
            or not re.fullmatch(r"[a-z]+\.(js|ts)", path.parts[1])
            or str(path) != self.file
            or path.suffix != (".js" if path.parts[0] == "javascript" else ".ts")
        ):
            raise ValueError("Invalid SAST corpus path")
        return self


def validate_inventory(source: Path, inventory: list[dict]) -> list[Case]:
    if not isinstance(inventory, list) or not inventory:
        raise ValueError("Empty or invalid SAST inventory")
    cases = [Case.model_validate(entry) for entry in inventory]
    declared = {(c.file, c.function): c for c in cases}
    if len(declared) != len(cases) or len({c.id for c in cases}) != len(cases):
        raise ValueError("Duplicate case or function")
    observed = {}
    files = {p for p in source.rglob("*") if p.suffix in {".js", ".ts"}}
    if {p.relative_to(source).as_posix() for p in files} != {c.file for c in cases}:
        raise ValueError("Inventory and source files differ")
    for file in files:
        if not file.resolve().is_relative_to(source.resolve()):
            raise ValueError("SAST corpus escapes source directory")
        relative = file.relative_to(source).as_posix()
        function = None
        for line in file.read_text(encoding="utf-8").splitlines():
            match = FUNCTION.match(line)
            if match:
                function = match[1]
                key = (relative, function)
                if key in observed:
                    raise ValueError("Duplicate source function")
                observed[key] = []
            marker = MARKER.fullmatch(line)
            if marker:
                if function is None:
                    raise ValueError("Annotation outside a case")
                observed[(relative, function)].append((marker[1], marker[2]))
    if set(observed) != set(declared):
        raise ValueError("Inventory and source functions differ")
    for key, case in declared.items():
        expected_marker = ("ruleid" if case.expected else "ok", case.rule)
        if observed[key] != [expected_marker]:
            raise ValueError(f"Missing, duplicate or wrong annotation: {case.id}")
    return cases


def verify(payload: dict, source: Path, inventory: list[dict]) -> dict:
    cases = validate_inventory(source, inventory)
    result = verify_locations(payload, source)
    dangerous = sum(c.expected for c in cases)
    if (
        result["dangerous_cases"] != dangerous
        or result["safe_cases"] != len(cases) - dangerous
    ):
        raise ValueError("Inventory totals do not match annotations")
    by_rule = {}
    for rule in sorted({c.rule for c in cases}):
        positives = sum(c.expected for c in cases if c.rule == rule)
        negatives = sum(not c.expected for c in cases if c.rule == rule)
        if not positives or not negatives:
            raise ValueError("Every rule needs dangerous and safe examples")
        by_rule[rule] = {
            "dangerous": positives,
            "safe": negatives,
            "findings": positives,
        }
    return {
        **result,
        "cases": len(cases),
        "by_rule": by_rule,
        "by_language": dict(
            sorted(Counter(PurePosixPath(c.file).suffix for c in cases).items())
        ),
        "false_positives": 0,
        "false_negatives": 0,
        "scope": "Only the reviewed corpus; not an estimate for arbitrary source code",
    }


def verify_run(base: Path = Path("runs")) -> dict:
    run_id = json.loads((base / "latest.json").read_text(encoding="utf-8"))["run_id"]
    repository = RunRepository(base)
    summary = repository.summary(run_id)
    if (
        summary["benchmark_id"] != "nosqli-sast-matrix"
        or summary["status"] != "completed"
    ):
        raise ValueError("Latest run is not a completed NoSQLi SAST matrix scan")
    source = Path(summary["source_path"])
    raw = base / run_id / "logs" / "raw_semgrep.json"
    inventory = json.loads(
        (config_directory() / "nosqli-sast-cases.json").read_text(encoding="utf-8")
    )
    result = verify(json.loads(raw.read_text(encoding="utf-8")), source, inventory)
    findings = repository.json(run_id, "findings.json")
    if summary["total"] != result["findings"] or len(findings) != result["findings"]:
        raise ValueError("Common report lost or duplicated findings")
    raw_findings = json.loads(raw.read_text(encoding="utf-8"))["results"]
    expected = Counter(
        (r["check_id"].rsplit(".", 1)[-1], f"{r['path']}:{r['start']['line']}")
        for r in raw_findings
    )
    actual = Counter((f["title"], f["location"]) for f in findings)
    if actual != expected or any(
        f["tool"] != "semgrep" or f["source"] != "SAST" for f in findings
    ):
        raise ValueError("Normalized findings differ from raw scanner locations")
    if summary["llm_usage"]["total"]["requests"] != 0:
        raise ValueError("LLM must remain disabled for acceptance")
    report = repository.text(run_id, "report.md")
    if any(rule not in report for rule in result["by_rule"]):
        raise ValueError("Markdown report is missing rule results")
    return {**result, "run_id": run_id, "llm_requests": 0}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, default=Path("runs"))
    args = parser.parse_args()
    print(json.dumps(verify_run(args.runs), indent=2))


if __name__ == "__main__":
    main()
