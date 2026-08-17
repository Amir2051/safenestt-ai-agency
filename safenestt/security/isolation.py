from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def allowed_workspace_root() -> Path:
    return repo_root()


def assert_path_under_safenestt_ai(path: Path) -> None:
    root = allowed_workspace_root().resolve()
    target = path.resolve()
    if root != target and root not in target.parents:
        raise PermissionError(f"Path {path} is outside SafeNestT AI workspace")


def production_isolation_check() -> bool:
    protected = Path("/home/ronzoro/safenestt-platform")
    return not protected.exists() or protected.is_symlink() is False
