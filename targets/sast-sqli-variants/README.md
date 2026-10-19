# SQLi variation regression

This suite contains 14 dangerous cases and 14 parameterized counterparts in
JavaScript, TypeScript, Python and PHP. Files are scanner input, not runnable
applications; they require no database or HTTP server.

Coverage includes renamed HTTP request objects, intermediate assignments, SQL
templates, percent formatting, `str.format`, bracket notation, headers, cookies,
Knex raw clauses, Django manager raw queries and PHP optional query arguments.

`ruleid:` marks the expected rule on the next source line. `ok:` marks a safe
counterpart. `benchmark.verify_sqli_variants` reads these annotations independently
of the Semgrep report, then checks every finding's file, rule and start line. Any
extra finding (including one in a safe file), scan error or skipped fixture fails
the check. Keep markers immediately above the SQL sink when editing fixtures.

The original 18 rules detected 4/14 dangerous cases in this suite. After expanding
sources and sinks in the existing rules, the local real Semgrep scan detected
14/14 with zero findings in safe files. These are curated regression results,
not an estimate of recall on arbitrary real applications.

The rules use HTTP-shaped attribute patterns, not a framework type checker.
Unrelated objects with similar attributes may match. Cross-function/cross-file
flows, arbitrary wrappers, custom sanitizers and dynamically generated SQL remain
outside the guarantee of this suite. Adding new frameworks requires new cases.

CI runs the real scanner before running the verifier. Synthetic unit tests only
check the verifier's rejection behavior and cannot replace that scan.
