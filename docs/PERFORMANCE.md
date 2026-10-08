# Synthe Commit: our own overhead

**These are the only performance numbers we quote.** They come from `scripts/bench_commit.py`,
and anyone can re-run it. We never borrow other papers' numbers for Synthe's speed.

## What was measured

The full commit path of one mediated `git_push`, 30 runs per path after 2 warm-up runs. Each run
uses a new signed, approved handoff that pushes one new commit to a new branch of a **local bare
repo** standing in for GitHub. Wall clock per phase; p50 and p95 are nearest-rank.

- **isolated**: the broker daemon (`synthe_commit.py serve`, a separate process) on a unix
  socket. The agent claims and proposes with `synthe_client`, and the commits travel as a thin git
  bundle (about 525 bytes here: one commit on top of `main`). Mode `none` on one OS user: the code
  path is the same as with a separate broker user, except the kernel uid check at admission.
- **in-process**: the dev path. The broker runs inside the caller's process and fetches the commit
  from the agent's repo by path.

```bash
python3 scripts/bench_commit.py --runs 30
```

## Results (2026-10-01, commit path as of Step B)

### macOS: Apple M2 Pro (10 cores), macOS 26.1, Python 3.13.5, git 2.55.0, cryptography 50.0.2

| Phase | isolated p50 | isolated p95 | in-process p50 | in-process p95 |
|---|---:|---:|---:|---:|
| claim (validate + reserve) | 1.7 ms | 2.4 ms | 1.4 ms | 1.8 ms |
| bundle (client: bases + git bundle) | 115.4 ms | 142.8 ms | 0.0 ms | 0.0 ms |
| transfer (socket, JSON, base64) | 0.6 ms | 1.0 ms | 0.0 ms | 0.0 ms |
| validate (commit-time re-check) | 0.9 ms | 1.1 ms | 0.6 ms | 0.8 ms |
| prepare (unpack bundle / fetch path) | 127.4 ms | 152.7 ms | 91.8 ms | 104.6 ms |
| fence (lock, claim, deps, record) | 0.9 ms | 1.3 ms | 0.9 ms | 1.1 ms |
| live check (remote state, ancestry) | 95.2 ms | 116.6 ms | 84.8 ms | 93.7 ms |
| inspect (every pushed path) | 31.4 ms | 45.4 ms | 28.1 ms | 32.8 ms |
| push (compare-and-swap) | 77.7 ms | 108.8 ms | 73.5 ms | 83.2 ms |
| confirm (re-read remote) | 22.8 ms | 30.3 ms | 21.0 ms | 25.1 ms |
| receipt (sign, append, fsync) | 0.9 ms | 1.4 ms | 0.9 ms | 1.3 ms |
| **total** | **485.4 ms** | **554.8 ms** | **309.7 ms** | **329.2 ms** |

### Linux: the same M2 Pro, in Docker Desktop's VM (Linux 6.10 aarch64), Python 3.12.14, git 2.47.3, cryptography 50.0.2

| Phase | isolated p50 | isolated p95 | in-process p50 | in-process p95 |
|---|---:|---:|---:|---:|
| claim (validate + reserve) | 1.2 ms | 1.4 ms | 0.8 ms | 1.1 ms |
| bundle (client: bases + git bundle) | 7.6 ms | 8.8 ms | 0.0 ms | 0.0 ms |
| transfer (socket, JSON, base64) | 0.4 ms | 0.5 ms | 0.0 ms | 0.0 ms |
| validate (commit-time re-check) | 0.6 ms | 0.7 ms | 0.5 ms | 0.6 ms |
| prepare (unpack bundle / fetch path) | 12.1 ms | 14.1 ms | 8.0 ms | 9.2 ms |
| fence (lock, claim, deps, record) | 0.5 ms | 0.7 ms | 0.5 ms | 0.7 ms |
| live check (remote state, ancestry) | 7.0 ms | 8.4 ms | 6.7 ms | 7.5 ms |
| inspect (every pushed path) | 2.0 ms | 2.5 ms | 1.8 ms | 1.9 ms |
| push (compare-and-swap) | 6.4 ms | 7.3 ms | 6.5 ms | 7.7 ms |
| confirm (re-read remote) | 1.6 ms | 1.9 ms | 1.6 ms | 1.9 ms |
| receipt (sign, append, fsync) | 1.2 ms | 1.8 ms | 1.6 ms | 2.0 ms |
| **total** | **40.3 ms** | **46.9 ms** | **28.0 ms** | **31.9 ms** |

## What the numbers say

- **Synthe's own decisions are cheap:** claim, commit-time re-validation (signature, policy,
  approvals), the fence and the signed receipt add up to about **4–5 ms** per push on both systems.
- **The rest is git work**, about a dozen `git` processes per push. Spawning a process costs far
  more on macOS than on Linux, which is why the same path takes about 0.5 s on the Mac and about
  40 ms on Linux.
- **Isolation costs one bundle round trip:** about **+12 ms** at p50 on Linux and **+176 ms** on
  macOS. The client creates the bundle (`bundle_bases` plus `git bundle`), and the broker verifies
  and unpacks it.
- **Obvious savings, not done yet:** answering `bundle_bases` and the new-branch live check with
  one `ls-remote` each instead of two, and checking the bundle's prerequisites in one `cat-file
  --batch-check`. Each saves a git process.

## What this does NOT measure (yet)

- **A real GitHub remote.** Network round trips are added to `bundle_bases`, live check, push and
  confirm (four or five round trips per push). Measuring that needs a real `feature/*` branch and
  Rishab's OK (`--remote-url`, Step H). Until then, don't quote a GitHub number.
- **Two OS users on macOS.** The Linux selftest runs the same path across two users; the extra
  cost is one `getsockopt` at admission.
- **Waiting for humans.** These numbers are the broker's cost per push. The "faster" claim is about
  removing the wait for approvals (speculative commit, approval templates), and it gets its own
  measured demo built on these numbers (Step D).

## How we may talk about it

- Yes: "Synthe's checks add about 5 ms per push; the whole commit path, git included, is about 40
  ms on Linux and about 0.5 s on a Mac against a local remote (our measurements, 2026-10-01)."
- No: any speed-up claim that isn't measured with this script or the Step D demo, or numbers
  borrowed from papers.

## Speculative commit vs approving each step (Step D, 2026-10-01)

`scripts/demo_async_approval.py`: 3 handoffs, each pushing one commit that needs a human's signed
approval, through the broker daemon (unix socket, bundles, signed receipts) on the M2 Pro above.
**Agent work (1.0 s per task) and human response time (3.0 s per request) are simulated sleeps**,
not measurements; Synthe's own steps are measured.

| Run | Wall clock | Synthe step p50 (measured) | Receipts |
|---|---:|---:|---|
| sequential: work, wait for approval, push | 14.29 s | 627 ms (bundle + propose + commit) | 6, chain ok |
| speculative: work, stage, approve in background | 8.29 s | 552 ms to stage; 360 ms to verify the approval and commit | 9, chain ok |

The 6.0 s saved is the human's response time overlapped with the agent's work, so it scales with
those two assumptions; we don't quote it as a general speed-up. What we do quote: staging adds
one receipt and about one dry-run commit check (p50 552 ms here, including the bundle), and the
commit after an approval costs p50 360 ms, less than a direct push because the commits are already
in the broker's mirror.

