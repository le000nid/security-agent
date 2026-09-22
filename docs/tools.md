# Curated scanner coverage

All rules and templates in this project are local and reviewed. They are a small
educational signal set, not a replacement for a security assessment.

## Nuclei DAST templates

Every template under `config/nuclei/` sends one GET request to `{{BaseURL}}`,
does not follow redirects, and does not carry a payload that modifies state.

| Template ID | Signal |
| --- | --- |
| `local-http-missing-content-type-options` | Missing `X-Content-Type-Options` |
| `local-http-missing-content-security-policy` | Missing `Content-Security-Policy` |
| `local-http-missing-frame-protection` | Neither `X-Frame-Options` nor CSP `frame-ancestors` is visible |
| `local-http-missing-referrer-policy` | Missing `Referrer-Policy` |
| `local-http-server-banner-disclosure` | Non-empty `Server` header |
| `local-http-permissive-cors-wildcard` | Literal wildcard CORS origin |
| `local-http-cookie-missing-httponly` | A cookie is set and no `HttpOnly` indicator is visible |
| `local-http-cookie-missing-samesite` | A cookie is set and no `SameSite` indicator is visible |
| `local-http-missing-cache-control` | Missing `Cache-Control` |

Cookie checks evaluate the combined response headers, so a response with several
cookies can require manual verification of each cookie. Findings are indicators,
not proof of exploitability.

## Semgrep SAST rules

| Rule ID | Signal | Confidence |
| --- | --- | --- |
| `python-debug-enabled` | Literal `debug=True` in an application run call | high |
| `python-subprocess-shell-true` | Standard subprocess API with `shell=True` | high |
| `python-unsafe-pickle-deserialization` | `pickle.load` or `pickle.loads` | high |
| `python-obvious-hardcoded-secret` | Obvious secret variable assigned a string literal | medium |
| `python-tls-verification-disabled` | `requests` call with `verify=False` | high |
| `javascript-tls-verification-disabled` | Object property `rejectUnauthorized: false` | high |
| `javascript-obvious-hardcoded-secret` | Obvious secret variable assigned a string literal | medium |
| `javascript-child-process-exec` | Direct `child_process.exec`/`execSync` call | medium |
| `javascript-eval-usage` | Direct `eval` call | high |

The sample under `targets/sample-app/` intentionally contains one example for
each rule. The benchmark only measures whether this curated fixture inventory is
detected; its precision/recall values do not measure real-world pentest quality.
