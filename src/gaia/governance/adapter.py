# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Governance adapter: entry point for action-level and workflow-level flows."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .exceptions import GaiaGovernanceError, InvalidResolutionError
from .protocols import (
    CheckpointRuntime,
    PolicyBindingProtocol,
    PolicyEngine,
    ReceiptServiceProtocol,
)
from .schemas import (
    ActionRequest,
    CheckpointResolution,
    GovernanceDecision,
    ReceiptRecord,
    TransitionOutcome,
    WorkflowTransition,
    new_id,
    utc_now_iso,
)


def _canonical_hash(payload: dict) -> str:
    """Stable SHA-256 of a JSON-canonicalized payload.

    Refuses non-canonical types rather than silently coercing them via
    ``default=str`` — an audit hash must be reproducible given the
    same logical content.
    """
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class GaiaGovernanceAdapter:
    """Compose a policy engine, checkpoint runtime, receipt service, and
    policy-version binding into a single entry point used by agents.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        checkpoint_runtime: CheckpointRuntime,
        receipt_service: ReceiptServiceProtocol,
        policy_binding: PolicyBindingProtocol,
    ) -> None:
        self.policy_engine = policy_engine
        self.checkpoint_runtime = checkpoint_runtime
        self.receipt_service = receipt_service
        self.policy_binding = policy_binding

    @classmethod
    def default(
        cls,
        audit_log: str | None = "receipts.jsonl",
        policy_version: str = "v0",
        constitution_hash: str = "constitution-dev",
    ) -> "GaiaGovernanceAdapter":
        """Pre-wired adapter using the in-repo reference implementations.

        Pass ``audit_log=None`` to use in-memory receipts (tests).
        Otherwise receipts are appended to the given JSONL path.
        """
        # Lazy imports avoid a circular namespace at package import time.
        from .checkpoint_bridge import InMemoryCheckpointBridge
        from .policy_binding import StaticPolicyBindingService
        from .receipt_service import InMemoryReceiptService, JsonlReceiptService
        from .stubs import RuleBasedPolicyEngine

        receipts: ReceiptServiceProtocol = (
            InMemoryReceiptService()
            if audit_log is None
            else JsonlReceiptService(audit_log)
        )
        return cls(
            policy_engine=RuleBasedPolicyEngine(policy_version=policy_version),
            checkpoint_runtime=InMemoryCheckpointBridge(),
            receipt_service=receipts,
            policy_binding=StaticPolicyBindingService(
                version=policy_version, constitution_hash=constitution_hash
            ),
        )

    def govern_action(self, action_request: ActionRequest) -> GovernanceDecision:
        return self.policy_engine.evaluate_action(action_request)

    def handle_transition(
        self, transition: WorkflowTransition, decision: GovernanceDecision
    ) -> TransitionOutcome:
        if decision.decision == "ALLOW":
            return TransitionOutcome(status="CONTINUE", reason="action allowed")
        if decision.decision == "BLOCK":
            receipt = self._issue_receipt(
                workflow_id=transition.workflow_id,
                checkpoint_id=None,
                decision="BLOCK",
                actor_id=None,
                evidence={
                    "transition": asdict(transition),
                    "decision": asdict(decision),
                },
            )
            return TransitionOutcome(
                status="TERMINATED",
                reason="action blocked",
                metadata={"receipt_id": receipt.receipt_id},
            )

        if decision.decision == "REVIEW":
            checkpoint = self.checkpoint_runtime.create_checkpoint(transition, decision)
            return TransitionOutcome(
                status="CHECKPOINT_OPEN",
                reason="review required",
                checkpoint_id=checkpoint.checkpoint_id,
                metadata={"checkpoint_id": checkpoint.checkpoint_id},
            )

        raise GaiaGovernanceError(f"unknown decision type: {decision.decision!r}")

    def resolve_checkpoint(
        self,
        checkpoint_id: str,
        resolution: CheckpointResolution,
        workflow_id: str,
    ) -> TransitionOutcome:
        # MED-4 fix: refuse to resolve a checkpoint whose stored workflow
        # does not match the caller's claimed workflow_id. The
        # CheckpointRuntime Protocol is extended with an optional
        # ``get_checkpoint`` method (duck-typed) for this validation;
        # runtimes that don't expose it skip the check.
        get = getattr(self.checkpoint_runtime, "get_checkpoint", None)
        if callable(get):
            record = get(checkpoint_id)
            if record is not None and record.workflow_id != workflow_id:
                raise InvalidResolutionError(
                    f"workflow mismatch: checkpoint {checkpoint_id} belongs to "
                    f"{record.workflow_id!r}, not {workflow_id!r}"
                )
        outcome = self.checkpoint_runtime.resolve_checkpoint(checkpoint_id, resolution)
        if outcome.status in {"RESUMED", "TERMINATED"}:
            receipt = self._issue_receipt(
                workflow_id=workflow_id,
                checkpoint_id=checkpoint_id,
                decision=resolution.resolution,
                actor_id=resolution.actor_id,
                evidence={
                    "resolution": asdict(resolution),
                    "outcome_status": outcome.status,
                },
            )
            merged = {**outcome.metadata, "receipt_id": receipt.receipt_id}
            return TransitionOutcome(
                status=outcome.status,
                reason=outcome.reason,
                checkpoint_id=outcome.checkpoint_id,
                metadata=merged,
            )
        return outcome

    def _issue_receipt(
        self,
        workflow_id: str,
        checkpoint_id: str | None,
        decision: str,
        actor_id: str | None,
        evidence: dict,
    ) -> ReceiptRecord:
        """Issue a receipt whose payload_hash covers the full evidence envelope.

        The hash input is canonicalized JSON of: receipt identity fields
        (decision, workflow_id, checkpoint_id, actor_id, policy_version,
        constitution_hash, timestamp) plus the supplied evidence. This
        means any tampering — to the decision, the action args, the
        policy version, the resolution actor, etc. — changes the hash.
        """
        policy_version = self.policy_binding.current_version()
        created_at = utc_now_iso()
        receipt_id = new_id("rcpt")
        envelope = {
            "receipt_id": receipt_id,
            "workflow_id": workflow_id,
            "checkpoint_id": checkpoint_id,
            "decision": decision,
            "actor_id": actor_id,
            "policy_version": policy_version.version,
            "constitution_hash": policy_version.constitution_hash,
            "created_at": created_at,
            "evidence": evidence,
        }
        payload_hash = _canonical_hash(envelope)
        record = ReceiptRecord(
            receipt_id=receipt_id,
            workflow_id=workflow_id,
            checkpoint_id=checkpoint_id,
            decision=decision,
            policy_version=policy_version.version,
            actor_id=actor_id,
            validator_set_id=None,
            created_at=created_at,
            payload_hash=payload_hash,
            metadata={
                "constitution_hash": policy_version.constitution_hash,
                "evidence": evidence,
            },
        )
        self.receipt_service.issue_receipt(record)
        return record
