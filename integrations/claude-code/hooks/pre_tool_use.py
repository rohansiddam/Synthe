#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Best-effort publishing guard, not a shell sandbox. The OS/credential wall is the enforcement boundary.

No command text is executed, logged or reflected into the response. Invalid hook input denies.
"""
import json
import re
import sys

MAX_INPUT = 256_000
RULES = [
    r"\bgit\b(?:\s+(?:-[cC]\s+\S+|--?[\w.-]+(?:=\S+)?))*\s+(?:push|send-pack|http-push)\b",
    r"[\"'`]git[\"'`]\s*,\s*\[?\s*(?:[\"'`][^\"'`\n]*[\"'`]\s*,\s*)*[\"'`]push[\"'`]",
    r"\bgh\s+(?:pr\s+merge|repo\s+sync|release\s+(?:create|upload|edit|delete))\b",
    # Conservatively intercept API calls, even reads: raw API publishing is outside this adapter.
    r"\bgh\s+api\b",
    r"\b(?:curl|wget|https?|xh)\b[^\n;|&]*api\.github\.com\b",
]


def denied(event):
    if not isinstance(event, dict) or event.get("hook_event_name") != "PreToolUse":
        return True
    tool = event.get("tool_name")
    if not isinstance(tool, str):
        return True
    if tool.endswith(("__synthe_submit_approval", "__github_publish")):
        return True
    if tool != "Bash":
        return False
    params = event.get("tool_input")
    if not isinstance(params, dict) or not isinstance(params.get("command"), str):
        return True
    command = re.sub(r"\\\r?\n", " ", params["command"])
    return any(re.search(rule, command) for rule in RULES)


def main():
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)
        block = len(raw) > MAX_INPUT or denied(json.loads(raw))
    except (ValueError, RecursionError):
        block = True
    if block:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
              "permissionDecisionReason": "Synthe: use synthe_propose_effect for publishing. Approval belongs in the human's account. Invalid hook inputs are refused."}}))
    # No allow decision: leave every other Claude permission check intact.
    return 0


if __name__ == "__main__":
    sys.exit(main())
