# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Receipt service reference implementations.

Two variants are shipped:

* :class:`InMemoryReceiptService` — ephemeral, for tests and in-process
  inspection.
* :class:`JsonlReceiptService` — append-only JSONL audit log on disk.
  Survives process exit and is trivially tailable / grep-able. This is
  the minimum viable shape for a real audit trail and is the default
  in the governed example.

Both implement :class:`gaia.governance.protocols.ReceiptServiceProtocol`.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from threading import Lock
from typing import Iterator

from .exceptions import GaiaGovernanceError
from .schemas import ReceiptRecord


class InMemoryReceiptService:
    """Process-local receipt store. Lost on exit."""

    def __init__(self) -> None:
        self._records: dict[str, ReceiptRecord] = {}

    def issue_receipt(self, record: ReceiptRecord) -> str:
        self._records[record.receipt_id] = record
        return record.receipt_id

    def get_receipt(self, receipt_id: str) -> ReceiptRecord:
        try:
            return self._records[receipt_id]
        except KeyError as exc:
            raise GaiaGovernanceError(f"receipt not found: {receipt_id}") from exc

    def __iter__(self) -> Iterator[ReceiptRecord]:
        return iter(self._records.values())


class JsonlReceiptService:
    """Append-only JSONL receipt log on disk.

    Each receipt is serialized as one JSON object per line. Opens the
    file in append mode, flushes on every write, and uses a process-local
    lock so concurrent in-process callers don't interleave lines.

    Intentionally not cross-process safe — use a dedicated receipt
    service (e.g. a log-forwarder or database) for multi-process
    deployments.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, ReceiptRecord] = {}
        self._lock = Lock()

    def issue_receipt(self, record: ReceiptRecord) -> str:
        line = json.dumps(asdict(record), default=str, sort_keys=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
            self._cache[record.receipt_id] = record
        return record.receipt_id

    def get_receipt(self, receipt_id: str) -> ReceiptRecord:
        if receipt_id in self._cache:
            return self._cache[receipt_id]
        # Cold-read path: scan the log. O(n) but acceptable for audit
        # queries and avoids loading the whole log eagerly.
        for record in self._read_all():
            if record.receipt_id == receipt_id:
                self._cache[receipt_id] = record
                return record
        raise GaiaGovernanceError(f"receipt not found: {receipt_id}")

    def _read_all(self) -> Iterator[ReceiptRecord]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                yield ReceiptRecord(**data)

    def __iter__(self) -> Iterator[ReceiptRecord]:
        return self._read_all()
