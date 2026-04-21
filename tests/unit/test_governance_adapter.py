# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Unit tests for GaiaGovernanceAdapter."""

from __future__ import annotations

from gaia.governance import (
    ActionRequest,
    CheckpointResolution,
    GaiaGovernanceAdapter,
    WorkflowTransition,
)
from gaia.governance.checkpoint_bridge import InMemoryCheckpointBridge
from gaia.governance.policy_binding import StaticPolicyBindingService
from gaia.governance.receipt_service import InMemoryReceiptService
from gaia.governance.stubs import RuleBasedPolicyEngine


def _adapter() -> GaiaGovernanceAdapter:
    return GaiaGovernanceAdapter(
        policy_engine=RuleBasedPolicyEngine(),
        checkpoint_runtime=InMemoryCheckpointBridge(),
        receipt_service=InMemoryReceiptService(),
        policy_binding=StaticPolicyBindingService(),
    )


def _action(tool_name: str, risk_tags: list[str]) -> ActionRequest:
    return ActionRequest(
        action_id="a1",
        actor_id="actor",
        tool_name=tool_name,
        action_type=tool_name,
        args={},
        risk_tags=risk_tags,
        workflow_id="wf_test",
    )


def _transition() -> WorkflowTransition:
    return WorkflowTransition(
        workflow_id="wf_test",
        transition_id="t1",
        from_state="START",
        to_state="RUN",
        transition_type="tool_call",
        related_action_id="a1",
    )


def test_allow_decision_is_pass_through():
    adapter = _adapter()
    decision = adapter.govern_action(_action("get_weather", []))
    assert decision.decision == "ALLOW"


def test_block_decision_for_blocked_tag():
    adapter = _adapter()
    decision = adapter.govern_action(_action("drop_table", ["blocked"]))
    assert decision.decision == "BLOCK"
    assert decision.policy_version == "v0"


def test_review_decision_for_review_tag():
    adapter = _adapter()
    decision = adapter.govern_action(_action("publish_post", ["review"]))
    assert decision.decision == "REVIEW"


def test_handle_transition_allow_continues():
    adapter = _adapter()
    decision = adapter.govern_action(_action("get_weather", []))
    outcome = adapter.handle_transition(_transition(), decision)
    assert outcome.status == "CONTINUE"


def test_handle_transition_block_issues_receipt():
    adapter = _adapter()
    decision = adapter.govern_action(_action("delete_all", ["blocked"]))
    outcome = adapter.handle_transition(_transition(), decision)
    assert outcome.status == "TERMINATED"
    assert "receipt_id" in outcome.metadata


def test_handle_transition_review_opens_checkpoint():
    adapter = _adapter()
    decision = adapter.govern_action(_action("publish_post", ["review"]))
    outcome = adapter.handle_transition(_transition(), decision)
    assert outcome.status == "CHECKPOINT_OPEN"
    assert outcome.checkpoint_id is not None


def test_resolve_checkpoint_approve_resumes_and_records_receipt():
    adapter = _adapter()
    decision = adapter.govern_action(_action("publish_post", ["review"]))
    opened = adapter.handle_transition(_transition(), decision)
    outcome = adapter.resolve_checkpoint(
        opened.checkpoint_id,
        CheckpointResolution(resolution="APPROVE", actor_id="reviewer", reason="ok"),
        workflow_id="wf_test",
    )
    assert outcome.status == "RESUMED"
    assert "receipt_id" in outcome.metadata
