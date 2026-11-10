"""Loads policy.yaml and exposes task scopes, critical resources and thresholds.

The file is parsed on every call so a demo can hot-edit policy.yaml without a
restart. Invalid or missing files fall back to safe built-in defaults.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = Path(os.environ.get("AYN_POLICY_PATH") or (BASE_DIR / "policy.yaml"))

DEFAULT_POLICY: dict[str, Any] = {
    "tasks": {
        "renew_permit": {
            "description": "Read a permit and renew it for a citizen.",
            "scopes": ["permits:read", "permits:update"],
        },
        "summarise_case_file": {
            "description": "Read one case file and summarise it. Nothing else.",
            "scopes": ["case_files:read"],
        },
    },
    "critical_resources": ["citizens"],
    "thresholds": {
        "max_calls_per_minute": 30,
        "max_denies_per_task": 3,
        "kill_on_critical_denied": True,
    },
}


def load_policy() -> dict[str, Any]:
    """Read and normalise policy.yaml. Never raises."""
    try:
        raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}

    raw_tasks = raw.get("tasks")
    tasks: dict[str, dict[str, Any]] = {}
    if isinstance(raw_tasks, dict):
        for name, cfg in raw_tasks.items():
            if not isinstance(cfg, dict):
                continue
            scopes = cfg.get("scopes") or []
            tasks[str(name)] = {
                "description": str(cfg.get("description", "")),
                "scopes": [s for s in scopes if isinstance(s, str)],
            }
    if not tasks:
        tasks = copy.deepcopy(DEFAULT_POLICY["tasks"])

    critical_raw = raw.get("critical_resources", DEFAULT_POLICY["critical_resources"])
    critical = (
        [str(r) for r in critical_raw if isinstance(r, str)]
        if isinstance(critical_raw, list)
        else list(DEFAULT_POLICY["critical_resources"])
    )

    thresholds = copy.deepcopy(DEFAULT_POLICY["thresholds"])
    raw_thresholds = raw.get("thresholds")
    if isinstance(raw_thresholds, dict):
        for key, default in DEFAULT_POLICY["thresholds"].items():
            value = raw_thresholds.get(key, default)
            if isinstance(default, bool):
                thresholds[key] = bool(value)
            else:
                try:
                    thresholds[key] = int(value)
                except (TypeError, ValueError):
                    thresholds[key] = default

    return {"tasks": tasks, "critical_resources": critical, "thresholds": thresholds}


def task_scopes(task: str) -> list[str] | None:
    """Allowed scopes for a task, or None if the task is unknown."""
    entry = load_policy()["tasks"].get(task)
    if entry is None:
        return None
    return list(entry["scopes"])


def task_description(task: str) -> str | None:
    entry = load_policy()["tasks"].get(task)
    return None if entry is None else str(entry.get("description", ""))


def known_tasks() -> list[str]:
    return sorted(load_policy()["tasks"].keys())


def critical_resources() -> list[str]:
    return list(load_policy()["critical_resources"])


def thresholds() -> dict[str, Any]:
    return dict(load_policy()["thresholds"])
