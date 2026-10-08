# Signed task submission in separate-user mode

## Problem

In macOS separate-user mode the broker owns its workspace, so `synthe-task`
must not write the pinned task artifact there directly. Making the workspace
user-writable would weaken the boundary: an agent could change a task after
the human signed it.

## Protocol

`synthe-task` builds the task text and handoff locally, pins the text by
SHA-256, and signs the handoff with the encrypted human approver key. It sends
only `{packet, content}` to the broker's `submit_task` operation. The broker:

1. accepts one UTF-8 Markdown artifact under `tasks/`, with a 64 KiB limit;
2. checks that the content hash equals the signed artifact hash;
3. writes the file with exclusive creation inside the configured workspace;
4. validates the signed handoff against the broker's live registry and
   receiver policy, deferring only the later approval-bound push; and
5. removes a newly created file if validation fails.

Submitting the same signed task and bytes again is idempotent. Reusing its
path with different bytes is refused. Symlinks, traversal, unsigned packets,
wrong hashes, unexpected artifact shapes, and non-human senders are refused.

## Boundary and non-goals

The socket peer identity controls who may reach the broker; the handoff
signature controls who may author a task. This operation never accepts a
claim token, approval, broker credential, arbitrary destination path, or git
effect. It does not approve or execute the later push.
