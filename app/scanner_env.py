"""Keep scanner defaults, cloud credentials and proxy settings out of lab runs."""

import os
from pathlib import Path


def scanner_environment(home: str) -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update(
        HOME=home,
        USERPROFILE=home,
        XDG_CONFIG_HOME=str(Path(home) / "config"),
        APPDATA=home,
        LOCALAPPDATA=home,
        SEMGREP_SEND_METRICS="off",
        SEMGREP_ENABLE_VERSION_CHECK="0",
        DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD="true",
    )
    return env
