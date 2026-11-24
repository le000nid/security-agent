"""Bounded CTF tool loop shared by every profile.

This package embeds the standalone CTF agents into the application core
instead of shipping them as separate task-named trees. One engine implements
the shared machinery — the model gateway, the JSON action contract, the
materials/file guard, the guarded HTTP layer and the finish validation —
while :mod:`app.agent.ctf.profiles` supplies the profile-specific behaviour
(hints, tool matrices, fallbacks) as plain data and small callables.

Architecture per profile:

    instruction + materials (+ live HTTP) -> LLM loop -> one JSON action
        -> fixed tool -> observation -> LLM ... -> finish (validated) -> flag.txt
"""

from app.agent.ctf.profiles import PROFILES, Profile
from app.agent.ctf.runtime import Session, run_profile

__all__ = ["PROFILES", "Profile", "Session", "run_profile"]
