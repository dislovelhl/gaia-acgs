# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Static PolicyBinding reference implementation.

Swap for constitutional-swarm's PolicyBinding once the policy control
plane is in place. The receipt issuer depends on this to stamp
policy-version + constitution-hash onto every decision.
"""
from __future__ import annotations

from dataclasses import replace

from .schemas import PolicyVersionRef, ReceiptRecord, utc_now_iso


class StaticPolicyBindingService:
    def __init__(
        self,
        version: str = "v0",
        constitution_hash: str = "constitution-dev",
    ) -> None:
        self._current = PolicyVersionRef(
            version=version,
            constitution_hash=constitution_hash,
            activated_at=utc_now_iso(),
        )

    def current_version(self) -> PolicyVersionRef:
        return self._current

    def bind_receipt(self, record: ReceiptRecord) -> ReceiptRecord:
        return replace(
            record,
            policy_version=self._current.version,
            metadata={
                **record.metadata,
                "constitution_hash": self._current.constitution_hash,
            },
        )
