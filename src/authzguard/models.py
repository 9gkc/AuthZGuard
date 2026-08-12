from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Check:
    identifier: str
    target: str
    method: str
    path: str
    identity: str
    expected_statuses: tuple[int, ...]
    rationale: str

    @property
    def url(self) -> str:
        return self.target.rstrip("/") + "/" + self.path.lstrip("/")


@dataclass(frozen=True)
class CheckResult:
    identifier: str
    url: str
    method: str
    identity: str
    expected_statuses: tuple[int, ...]
    observed_status: int | None
    passed: bool
    note: str
    content_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

