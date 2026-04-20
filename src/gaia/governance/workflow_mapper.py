# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Maps a GAIA workflow event into a governance WorkflowTransition.

Included in PR 1 as a future-hook seam for constitutional-swarm. The
base agent loop does not currently emit workflow events; callers can
use this mapper once such events exist.
"""
from __future__ import annotations

from typing import Any

from .schemas import WorkflowTransition, new_id


def map_gaia_event_to_transition(
    event_name: str,
    payload: dict[str, Any],
    workflow_context: dict[str, Any],
) -> WorkflowTransition:
    return WorkflowTransition(
        workflow_id=workflow_context["workflow_id"],
        transition_id=workflow_context.get("transition_id", new_id("transition")),
        from_state=workflow_context.get("from_state", "UNKNOWN"),
        to_state=workflow_context.get("to_state", event_name.upper()),
        transition_type=event_name,
        related_action_id=workflow_context.get("related_action_id"),
        payload=dict(payload),
    )
