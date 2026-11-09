# LFI regression: local PHP file inclusion

This suite has 14 dangerous cases and 14 safe counterparts in 10 PHP files.
The files are scanner input, not runnable applications. No PHP runtime, included
files, database or web server is required.

Coverage:

- GET, POST, REQUEST and COOKIE input, aliases and constructed paths;
- `filter_input` with INPUT_GET, INPUT_POST and INPUT_COOKIE;
- all four include/require forms, including assignment and return expressions;
- `basename` and one-pass `../` replacement, neither treated as an allowlist;
- fixed literal paths, conditional choices and constant path dictionaries;
- dictionaries containing a tainted value or overwritten with user input.

On this same final suite, the original rule detected 9/14 dangerous cases and
reported one false positive in a safe dictionary lookup. The updated existing
rule detects 14/14, with zero findings in the safe fixtures. There are still
18 rules overall. These are curated regression results, not general recall.

The new HTTP input sources use `exact: true`. The LFI rule alone enables
`taint_assume_safe_indexes`: a user-selected key does not taint an otherwise
untainted dictionary value, while tainted dictionary values remain unsafe.
This behavior is described in the official
[Semgrep documentation](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/advanced#assume-tainted-indexes-are-safe).
The two dangerous dictionary cases guard against accidentally suppressing all
array-based paths. No blanket sanitizer is added for `basename`, `realpath`,
`str_replace` or `filter_input`.

`ruleid:` marks the expected rule on the following line; `ok:` marks a safe
counterpart. `python -m benchmark.verify_lfi_variants logs/lfi-variants.json`
checks an actual JSON scan against these independent annotations. Wrong rules,
lines, missing fixtures, scanner errors and any extra findings fail the check.
SQLi and LFI share the acceptance-checking logic in `benchmark.annotated_scan`.

This suite checks HTTP input reaching PHP inclusion constructs. Generic file
reads/path traversal, uploads, template engines, framework wrappers, arbitrary
cross-function/cross-file flows and custom path validation need separate cases.
RFI literal-URL detection is unchanged and remains in the original benchmark.
