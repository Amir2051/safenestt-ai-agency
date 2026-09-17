from __future__ import annotations

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import safenestt  # noqa: E402
import safenestt.security.permissions as _permissions_mod  # noqa: E402

print("[conftest] safenestt:", safenestt.__file__, file=sys.stderr)
print("[conftest] permissions:", _permissions_mod.__file__, file=sys.stderr)
