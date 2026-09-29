from __future__ import annotations

import json
from pathlib import Path

from .store import InvestigationStore


def save_snapshot(store: InvestigationStore, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(store.snapshot(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def load_snapshot(path: str | Path) -> InvestigationStore:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return InvestigationStore.restore(data)
