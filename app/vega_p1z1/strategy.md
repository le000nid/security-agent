# P1Z1: First run

The runner reads regular text files recursively from VEGA_TASK_DIR/materials.
It does not use a fixed filename, a fixed key, or a required flag prefix.
UTF-8 (including BOM) and Windows-1251 text are supported. Symlinks and binary
content are skipped. Limits: 64 text files, 64 KiB per file, 120000 characters
in the combined context, and a 170-second application time budget.

The file contents are sent as untrusted data to the model named by
LOCAL_AGENT_MODEL, via OPENAI_BASE_URL/chat/completions. Authorization uses
OPENAI_API_KEY and X-VEGA-Agent-Session uses VEGA_AGENT_SESSION_ID. Credentials
are never written into the archive, prompts, or logs. Redirects are refused.

The model compares all files and returns a source ID and the exact key value.
The runner accepts only a nonempty value actually present in that source.
It writes that UTF-8 value, without adding a newline, to
VEGA_CTF_ARTIFACT_DIR/flag.txt using an atomic replacement.

There is no heuristic-only success path: at least one successful model response
and a validated selection are required. Up to three attempts handle transport
and response errors. A failed run exits nonzero and does not leave a stale flag.
Input files are never executed, and embedded instructions never grant tools.

agent.json records this application's metadata; the PDF provides no additional
manifest schema. This submission uses the published bash run.sh launch contract.
