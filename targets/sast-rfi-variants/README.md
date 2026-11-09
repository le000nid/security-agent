# RFI regression: PHP inclusion of HTTP(S) addresses

This suite has 14 dangerous cases and 14 counterparts that do not include an
HTTP(S) address, in eight PHP files. These are source inputs for Semgrep; PHP
is never executed and the `.invalid` hosts are never contacted.

The original rule detected 8/14 dangerous cases on this suite, with no findings
in the safe files. The updated existing rule detects 14/14, also with zero safe
file findings. There are still 18 rules in the full configuration.

The RFI rule now tracks HTTP(S)-prefixed string values into all four PHP
include/require constructs. Cases cover literals, aliases, concatenation,
interpolation, sprintf, conditional choices, arrays, expression return values
and reintroducing a remote prefix after extracting a filename or URL path.

RFI-specific exclusions cover basename, parse_url with PHP_URL_PATH, and
concatenation starting with a fixed local directory prefix. They are NOT LFI
sanitizers: reducing a path to a basename does not establish an allowed file.
The dangerous reconstruction cases verify that adding a fresh HTTP(S) prefix
after such transformations is still reported. An HTTP(S) value used only as
an index into an otherwise fixed local path table does not make it remote.

`ruleid:` and `ok:` annotations specify expected behavior independently from
scanner output. `python -m benchmark.verify_rfi_variants logs/rfi-variants.json`
checks exact file/rule/line triples, full fixture coverage and scanner errors.
CI runs a real Semgrep scan before this verifier; unit tests check its rejection
behavior, not the scanner's detection ability.

These are potential remote-inclusion findings, not proof of code execution.
PHP's URL include behavior depends on runtime settings and wrapper support;
see the official [include manual](https://www.php.net/manual/en/function.include.php)
and [filesystem configuration](https://www.php.net/manual/en/filesystem.configuration.php).
The rule focuses on HTTP(S), not FTP, data/phar/zip wrappers, encoded URLs,
arbitrary cross-function flows or custom loaders. Those require separate cases.
LFI continues to handle the separately modelled HTTP-input-to-include flows.
