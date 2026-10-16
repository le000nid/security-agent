# SAST scanner output contract

The Semgrep adapter accepts a successful scan only when the JSON has a results
array, an empty errors array and a nonempty `paths.scanned` array. A scan that
processed no eligible source files is a failure, even when results is empty.
Check the selected source, supported languages and scan filters in that case.

If the scanner reports skipped configured rules, the adapter rejects the scan.
This does not prohibit every ignored file: unsupported extensions, configured
excludes and language coverage still need review. Nonempty scanned paths alone
do not prove that every source file in a project was analyzed.

Finding IDs must be nonempty strings. Every finding must refer to a scanned
path and have a positive integer line; a supplied column must also be a positive
integer. Booleans are not coordinates. Duplicate JSON fields are rejected,
including duplicates that would overwrite findings with an empty results array.
UTF-8 BOM and Unicode source paths are accepted.

Malformed and incomplete responses propagate through the existing SAST failure
handling: nonzero run exit code, failed SAST status and a saved failure report.
The adapter does not turn such responses into a successful zero-finding result.
An empty results array remains valid when the scan coverage metadata is present.

Tests cover the parser boundary and four additional end-to-end simulated scanner
failures. Earlier scanner mocks were updated to carry the same errors and scanned
paths fields as the project's real Semgrep JSON, rather than incomplete stubs.
These checks concern the SAST adapter and require no API/UI changes.
