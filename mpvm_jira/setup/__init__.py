"""Interactive configuration wizard for MaxPatrol VM and Jira."""

from __future__ import annotations

import sys
from pathlib import Path


def run_setup(base_dir: Path) -> int:
    """Run the full-screen setup wizard in ``base_dir``."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print(
            "Команда setup требует интерактивный терминал. "
            "Используйте ручную настройку из README.",
            file=sys.stderr,
        )
        return 2
    from .app import SetupWizardApp

    app = SetupWizardApp(base_dir=base_dir)
    app.run()
    return int(app.return_code or 0)


__all__ = ["run_setup"]
