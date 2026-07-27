# Ouroboros

[![GitHub stars](https://img.shields.io/github/stars/razzant/ouroboros?style=flat&logo=github)](https://github.com/razzant/ouroboros/stargazers)
[![Downloads](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Frazzant%2Fouroboros%2Fbadges%2Fdownloads.json)](https://github.com/razzant/ouroboros/releases)
[![Website](https://img.shields.io/badge/website-razzant.github.io%2Fouroboros-c93545.svg)](https://razzant.github.io/ouroboros/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![macOS 12+](https://img.shields.io/badge/macOS-12%2B-black.svg)](https://github.com/razzant/ouroboros/releases)
[![Linux](https://img.shields.io/badge/Linux-x86__64-orange.svg)](https://github.com/razzant/ouroboros/releases)
[![Windows](https://img.shields.io/badge/Windows-x64-blue.svg)](https://github.com/razzant/ouroboros/releases)
[![OuroborosHub](https://img.shields.io/badge/OuroborosHub-skills%20marketplace-8A2BE2.svg)](https://github.com/razzant/OuroborosHub)
[![Version 6.81.0](https://img.shields.io/badge/version-6.81.0-green.svg)](VERSION)

Ouroboros is an open-source, general-purpose AI agent whose identity, durable memory, and history continue across tasks and restarts. It works on external projects, coordinates a live swarm of specialist agents, and can rewrite the implementation it runs on, including its code, architecture, prompts, tools, and dependencies. Reflection can also change how it understands itself without severing that continuity.

It runs as a native desktop app or through a headless CLI. The runtime keeps its repository, durable memory, history, and interface on your machine, while model inference can use remote APIs you configure or a local GGUF model.

Ouroboros first booted on February 16, 2026. During the following 48 hours, the repository advanced from the v4.1 line to v6.2.0. The self-authored record preserved from that period counts 32 evolution cycles. That first generation ran in Google Colab through Telegram and remains preserved on the [`legacy-google-colab`](https://github.com/razzant/ouroboros/tree/legacy-google-colab) branch and its [original project page](https://razzant.github.io/ouroboros/archive/first-generation/); the current generation carries the same identity into a native desktop and headless runtime.

> ⭐ **[Star Ouroboros](https://github.com/razzant/ouroboros)** to follow its next evolution. A star also helps more people find the project, trace its history, and take part in what it becomes.

Reviewed skills, transport bridges, tools, and widgets are available through [OuroborosHub](https://github.com/razzant/OuroborosHub).

<p align="center">
  <img src="assets/chat.png" width="700" alt="Chat interface">
</p>
<p align="center">
  <img src="assets/settings.png" width="700" alt="Settings page">
</p>

---

## Install

| Platform | Download | Instructions |
|----------|----------|--------------|
| **macOS** 12+ | [Ouroboros.dmg](https://github.com/razzant/ouroboros/releases/latest) | Open DMG → drag to Applications → optional CLI: run `Install CLI.command` after the app is in Applications |
| **Linux** x86_64 | [Ouroboros-linux.tar.gz](https://github.com/razzant/ouroboros/releases/latest) | Extract → run `./Ouroboros/Ouroboros` → optional CLI: `./Ouroboros/bin/install-ouroboros-cli`. If browser tools fail due to missing system libs, run: `./Ouroboros/python-standalone/bin/python3 -m playwright install-deps chromium webkit` |
| **Windows** x64 | [Ouroboros-windows.zip](https://github.com/razzant/ouroboros/releases/latest) | Extract → run `Ouroboros\Ouroboros.exe` → optional CLI: `Ouroboros\bin\install-ouroboros-cli.cmd` |

Prerelease artifacts stay on their tag pages; `/releases/latest` points to the latest stable release.

<p align="center">
  <img src="assets/setup.png" width="500" alt="Drag Ouroboros.app to install">
</p>

On macOS, use right-click → **Open** on first launch if Gatekeeper asks. The setup wizard configures model access, review policy, and budget. Packaged CLI installers create a user-local `ouroboros` command without sudo; `ouroboros run --start "2+2?"` starts or attaches to the same managed runtime used by the desktop app.

---

## What Ouroboros Can Do

- **Modify its implementation.** Its editable surface spans application code, architecture, prompts, tools, and dependencies, while reflection can also reshape its living self-understanding.
- **Evolve autonomously.** Evolution campaigns turn selected improvements into reviewed changes that remain part of its Git history.
- **Continue across restarts.** Identity, memory, dialogue, knowledge, reflections, and version history form one ongoing biography.
- **Think between requests.** Background consciousness supports reflection, initiative, and preparation outside the immediate request-response loop.
- **Coordinate a live swarm.** Specialist agents can investigate or act in parallel, share task-tree findings, and return work for integration.
- **Work on external projects.** A separate Git workspace can receive the full task loop while Ouroboros keeps its own repository and governance boundary distinct.
- **Operate through desktop or CLI.** The native app and gateway-backed command line expose the same managed tasks, progress, artifacts, logs, and schedules.
- **Organize long-running work.** Project rooms keep working folders, journals, knowledge, task history, and conversations connected to the same identity.
- **Use remote or local models.** Supported provider APIs and local GGUF models can fill the runtime's configurable cognitive roles.
- **Grow through reviewed extensions.** Skills, transport bridges, widgets, MCP tools, and companion processes expand capability without folding every integration into the core.
- **Keep self-change inspectable.** Git history, review evidence, explicit protected surfaces, and restart checks make implementation changes traceable.

This list is an orientation, not a second specification. [BIBLE.md](BIBLE.md) defines Ouroboros's identity and constitutional boundaries; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) are the current technical sources of truth.

---

## Run from Source

### Requirements

- Python 3.10+
- macOS, Linux, or Windows
- Git
- [GitHub CLI (`gh`)](https://cli.github.com/), optional unless you use GitHub integration

### Setup

```bash
git clone https://github.com/razzant/ouroboros.git
cd ouroboros
python3.11 -m venv .venv      # any Python >= 3.10 is OK
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e . --no-deps
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv      # any Python >= 3.10 is OK
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e . --no-deps
```

### Run

```bash
ouroboros server
```

Then open `http://127.0.0.1:8765` in your browser. The setup wizard will guide you through API key configuration.

### Google Colab

Use [`notebooks/colab_quickstart.py`](notebooks/colab_quickstart.py) as a Colab-compatible cell script when you need a source-mode runtime without the desktop UI. It keeps runtime data on Google Drive and preserves the original Colab path without making it the primary installation flow.

### CLI / Headless

The `ouroboros` command attaches to the local runtime by default and starts one when `--start` is passed. It exposes managed tasks, progress streams, artifacts, logs, schedules, settings, skills, and evolution controls without duplicating the server's business logic.

```bash
ouroboros status
ouroboros run --start "2+2?"
ouroboros run "Summarize current runtime state"
ouroboros run --workspace /path/to/project --memory-mode forked --patch-out result.patch "Fix the failing test"
ouroboros tasks list
ouroboros logs tail progress --task-id <task_id>
ouroboros schedule add --name nightly-review --cron "0 2 * * *" "Run a maintenance review"
ouroboros schedule list
```

External workspaces must be separate Git worktree roots and may not overlap Ouroboros's own repository or data directory. Patch, streaming, detached-task, and schedule semantics are documented in the CLI help and the canonical [architecture](docs/ARCHITECTURE.md).

### Remote SSH Projects

Remote SSH workspaces keep one Ouroboros mind on **Home**: models, identity,
memory, policy, review, task state, provider/MCP credentials, and the UI/CLI all
remain on the machine running Ouroboros. A restricted `ouroboros-execd` runs
native file, Git, and process operations in the selected remote Git worktree.
Local and SSH projects expose the same model-facing tool names and schemas;
placement changes the executor, not the model's faculty set.

Setup is owner-driven:

1. Configure an ordinary alias in Home's `~/.ssh/config` and complete its first
   host-key, password, or MFA interaction in a normal terminal. Ouroboros uses
   local OpenSSH and `ssh-agent`; it neither stores nor uploads SSH credentials.
2. Configure an Ouroboros **Network Password** and restart. The owner-only
   connection API requires it even on loopback; this password authenticates
   Settings/CLI to Ouroboros and is unrelated to SSH authentication.
3. Open **Settings → Connections**, add the alias, then **Test** and
   **Bootstrap** it. Bootstrap uploads the matching standalone executor from
   Home, so the target needs no Python, `sudo`, systemd, listening port, or
   outbound internet. Test is only a transport/platform probe: it does not pin
   target identity or make the connection selectable. The first successful
   Bootstrap performs the execd handshake, pins continuity, and records healthy
   compatibility for the current Home process.
4. Create a Project, choose **SSH**, select the healthy connection, browse to
   the remote folder, and attach its Git worktree. Remote tasks are
   Project-only and keep that placement for their lifetime.

The thin CLI provides the same six owner-administration actions:

```bash
ouroboros connections list [--json]
ouroboros connections add --name NAME --ssh-alias ALIAS [--json]
ouroboros connections test ID [--json]
ouroboros connections bootstrap ID [--json]
ouroboros connections retrust ID [--json]
ouroboros connections retire ID [--json]
```

These commands prompt for the Network Password on a controlling terminal. The
CLI intentionally has no remote task runner, terminal, or TUI; create/select
remote Projects in the UI and work in their ordinary Project room.

V1 execd targets are GNU/glibc Linux `x86_64` and `aarch64` (glibc 2.17 or
newer). macOS/Windows targets, Alpine/musl, non-Git folders, remote desktop,
general SOCKS/private-network proxying, arbitrary remote environment injection,
and task handoff between machines are not supported. Shell commands run with
the selected remote Unix account's authority; execd is a placement and custody
boundary, not a container sandbox.

OpenSSH `known_hosts` remains the transport trust authority. Ouroboros
additionally pins execd's continuity ID after the first successful Bootstrap;
Test never changes that pin. This ID is not a hardware identity or a
replacement for `known_hosts`. If it changes, verify the host through normal
OpenSSH first, then use **Retrust** and confirm the old/new IDs while no task or
lease is active. Live compatibility/health evidence is intentionally
process-local, so after restarting Home run the fast Bootstrap check again
before selecting that connection for a new Project. **Reconnect** is a separate
UI action for rebuilding and reconciling already admitted Project sessions; it
is not another name for Test and is intentionally absent from the six-command
owner CLI.

Common setup failures are intentionally fail-closed:

- **Auth/host trust:** run `ssh ALIAS true` in a normal Home terminal, resolve
  the prompt there, then Test again. Ouroboros never answers interactive SSH
  prompts.
- **Owner auth not configured:** set the Network Password in Settings, restart,
  sign in, and reopen Connections. CLI commands cannot take it from argv,
  environment variables, or a pipe.
- **Unsupported platform or missing bundle:** use a supported GNU/glibc target
  and an Ouroboros build that contains the matching execd asset; Bootstrap
  never falls back to remote Python.
- **Host/workspace identity changed:** do not bypass the mismatch. Verify the
  machine or Git worktree replacement, then Retrust or rebind the Project.
- **`completion_unknown`:** transport ended after a mutation may have started.
  Inspect the task's diagnostic, request ID, stdout/stderr, and imported
  artifacts before retrying; Ouroboros does not blindly repeat it.

For failure phases, lifecycle behavior, data locations, credential boundaries,
browser loopback forwarding, and troubleshooting, see
[Remote SSH workspace placement](docs/ARCHITECTURE.md#remote-ssh-workspace-placement).

### For Agents

Another agent, script, or CI job can invoke Ouroboros through the same gateway-backed CLI:

```bash
ouroboros run --start \
  --workspace /path/to/project \
  --memory-mode forked \
  --patch-out result.patch \
  --result-json-out result.json \
  "Investigate the task, act, and verify the result"
```

Use `--jsonl` for a machine-readable event stream and `--detach` when the caller will follow the task with `ouroboros tasks watch <task_id>` or inspect it with `ouroboros tasks show <task_id>`. External workspace runs keep Ouroboros's own repository and governance context separate, then export changes as reviewable patch artifacts.

To change Ouroboros itself, follow [CONTRIBUTING.md](CONTRIBUTING.md) and read [BIBLE.md](BIBLE.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md), and [docs/CHECKLISTS.md](docs/CHECKLISTS.md) in full before editing.

### Configuration

The first-run wizard and **Settings** configure model access, cognitive roles, local models, review policy, runtime mode, budget, skills, and optional integrations. Ouroboros supports configurable remote providers, compatible endpoints, and local GGUF inference; exact settings and defaults live in [`ouroboros/config.py`](ouroboros/config.py) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

The server binds to `127.0.0.1:8765` by default. Read [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) before exposing it beyond loopback; non-local binds need `OUROBOROS_NETWORK_PASSWORD` or an explicitly trusted external access layer.

### Run Tests

```bash
make test
```

---

## Build

### Docker

```bash
docker build -t ouroboros-web .
docker run --rm -p 8765:8765 \
  -e OUROBOROS_NETWORK_PASSWORD='choose-a-password' \
  -e OUROBOROS_FILE_BROWSER_DEFAULT=/workspace \
  -v "$PWD:/workspace" \
  ouroboros-web
```

Docker runs the web runtime, not the native desktop shell. It bundles Chromium and WebKit support; use [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for network and container policy.

### Release tag prerequisite

Platform build scripts package only a commit already tagged with `v$(cat VERSION)`. Tag the exact release commit first:

```bash
git tag -a "v$(tr -d '[:space:]' < VERSION)" -m "Release v$(tr -d '[:space:]' < VERSION)"
```

`scripts/build_repo_bundle.py` verifies the tag and embeds the source binding into the packaged repository bundle. Signing, notarization, bytecode sealing, and CI invariants are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

### macOS (.dmg)

```bash
bash scripts/download_python_standalone.sh
OUROBOROS_SIGN=0 bash build.sh
```

Output: `dist/Ouroboros-<VERSION>.dmg`, containing `Ouroboros.app` and `Install CLI.command`. Omit `OUROBOROS_SIGN=0` when a Developer ID signing identity is configured.

### Linux (.tar.gz)

```bash
bash scripts/download_python_standalone.sh
bash build_linux.sh
```

Output: `dist/Ouroboros-<VERSION>-linux-<arch>.tar.gz`, containing `Ouroboros/bin/install-ouroboros-cli`. If bundled browser tools need host libraries, run `./Ouroboros/python-standalone/bin/python3 -m playwright install-deps chromium webkit`.

### Windows (.zip)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/download_python_standalone.ps1
powershell -ExecutionPolicy Bypass -File build_windows.ps1
```

Output: `dist\Ouroboros-<VERSION>-windows-x64.zip`, containing `Ouroboros\bin\install-ouroboros-cli.cmd`.


## Architecture and Runtime Data

The native launcher starts a web runtime and supervisor-managed agent workers. The agent core lives in `ouroboros/`, the interface in `web/`, the process plane in `supervisor/`, and the runtime's durable identity, state, history, logs, and skills under `~/Ouroboros/data/`.

The full component map, data flow, API surface, storage layout, safety boundary, and operational rationale live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Deployment details live in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Runtime Commands

| Command | Purpose |
|---------|---------|
| `/panic` | Stop the runtime and its managed processes immediately. |
| `/restart` | Restart without automatically resuming the active owner task. |
| `/status` | Show workers, task queue, and budget state. |
| `/evolve on\|off` | Start or stop autonomous evolution. |
| `/review` | Queue a deep constitutional and architectural self-review. |
| `/bg start\|stop\|status` | Control background consciousness. |


## Philosophy

The 13 Constitution principles — Agency, Continuity, Meta-over-Patch,
Immune Integrity, Self-Creation, LLM-First, Authenticity & Reality
Discipline, Minimalism, Becoming, Versioning and Releases, the absorbed
Iterations / Spiral lineage, and Epistemic Stability — are defined in
full in [`BIBLE.md`](BIBLE.md). That file is the constitutional SSOT
(Bible P4 Ship-of-Theseus protection) and this README intentionally does
not paraphrase it.

---

## Contributing

External contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the complete workflow. Open pull requests against the lowercase
`ouroboros` branch and leave release-version allocation to maintainers. A
current OpenRouter triad + scope packet is the optional fast path; pull
requests without one remain welcome but require more maintainer-side review
and integration work.

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 6.81.0 | 2026-07-26 | **feat: the benchmark-provenance campaign lands as one release** — every launcher admits at a shared gate before touching the filesystem and finalizes a typed outcome on every path; one structural audit enforces that boundary, confinement from the active checkout, and a single manifest publisher across all fourteen launchers; harness exit codes are no longer trusted as run status; the acceptance dialogue reconciles receipts through one typed identity; prompt caching is normalized at every send site; and the owner's context mode becomes explicit and fail-closed. Disclosed limits live in each bench's METHODOLOGY.md. |
| 6.80.0 | 2026-07-25 | **feat: the review system learns its own limits — measured tokenizer density, reachable Capability Evidence for pinned reviewers, and fail-fast plan-review binding.** (1) The hardcoded `CLAUDE_REAL_TOKENS_PER_ESTIMATED = 1.65` multiplier and its substring family gate are GONE: real tokenizer density is now MEASURED at the physical send boundary and stored in a new `capability_evidence.json` `token_density` namespace (normalized model identity key, bounded raw-pair retention, throttled writes, cache-bearing usage skipped because Anthropic excludes cache tokens from `input_tokens`). `calibrated_input_token_limit` takes the STRICTEST of budget cap / density form / historical margin form, so every review surface (scope, triad, plan, deep) sizes packs at or below today's caps and a model with no observation sizes DOWN from a documented conservative cold-start density instead of up from a chars/4 guess; that cold-start density bounds the COLD path ONLY — it is Claude-derived, and flooring every model with it permanently shrank the pack of any lighter tokenizer (an all-GPT scope + triad lost ~27% / ~36%) with no way for measurement to correct the direction. "Measurement can only ever TIGHTEN" is instead enforced PER MODEL IDENTITY in the store, which keeps the running MAXIMUM: one identity collects observations from every surface (the shipped reviewer is both the scope slot and a triad slot), so a run of prose-dominated doc-only packs would otherwise pull the stored density down and hand the next code-heavy pack a looser cap; the historical absolute-margin form still bounds every cap, so none exceeds its pre-measurement value; the scope limit is computed per CALL (an import-time constant froze the pre-measurement value for the whole process). The main loop's `context_fit` projection deliberately does NOT use the cold density — the baseline for an unmeasured route is the neutral 1.0, so unknown routes keep trying Max (BIBLE P1) and fresh installs and isolated benchmark servers are not demoted; the measured density supersedes that baseline from the first successful send of a model onward, restoring the old proactive max→low protection as a measurement instead of a guess. Disclosed residual: the only exposed window is a FIRST round whose prompt already exceeds the calibrated window on a fresh evidence store — it fails once with `context_overflow`, after which `loop.py`'s existing one-shot task-local Low reprojection retries the same model, and the density is measured from then on. A cache-bearing send is still measurable on every provider whose `prompt_tokens` is cache-inclusive (the assumption `pricing.py` already encodes); only the direct-Anthropic and GigaChat paths, which report cache tokens outside `prompt_tokens`, are skipped — without that provider scoping the measurement path would have been vacuous, since the main loop and every review surface always mark a cached prefix. (2) Capability Evidence became REACHABLE for a pinned reviewer: a scope-slot change makes settings-save probe that slot's OWN route and return the existing `needs_ack:{route, route_fp, evidence}` contract, which `settings.js` RENDERS through the same confirm -> owner-capability-ack flow the Max gate already uses (an unrendered payload left the owner staring at `SCOPE_REVIEW_SUB_FLOOR` telling them to ack a route the UI never offered), an off-default pin gets one lazy metadata-only probe, both surfaces are ROUTE-aware rather than model-aware (the lazy probe memoises by route fingerprint and the notice fires on a base-URL change too, reading the slot from the candidate settings — keyed by model alone, a hot `OPENAI_BASE_URL` change left an unprobed route with no notice and a silent fall to the sub-floor), a stored singular `OUROBOROS_SCOPE_REVIEW_MODEL` is promoted into the plural BEFORE defaults are applied (the plural default was silently beating the owner's pin), and unrecognised review model ids are reported loudly on save. Fail-closed on absent evidence is unchanged, and a pin is still routing intent, never an owner-ack. (3) Scope review is no longer performed at all in owner-selected `low` context mode — read from the OWNER-selected mode (`get_owner_context_mode`), never the effective one, so the friction-free Max→Low auto-downgrade that a plain agent-reachable `/api/settings` model change can trigger narrows context sizing exactly as before while leaving scope review ON (the downgrade is recorded as derived `OUROBOROS_CONTEXT_MODE_AUTO_LOW` state, merge-skipped in both directions and cleared only by an explicit owner selection; that flag is TRI-STATE and an ABSENT one resolves FAIL-CLOSED to gate-ON, so neither a `settings.json` predating this release nor an isolated benchmark server can silently declare a scope-review skip — the three benchmark env allowlists now forward the flag with the mode — and `/api/state` publishes it as `context_mode_auto_low` so re-selecting `Low` on an auto-downgraded install is no longer short-circuited away from the endpoint that clears it) — an owner policy coupling recorded as a typed `scope_review status="skipped_low_context_mode"` row on the same review-evidence surface, with the triad's blocking staged-diff review unchanged in every mode. `OUROBOROS_SCOPE_REVIEW_FLOOR` becomes DEPRECATED and ENFORCEMENT-INERT rather than removed (owner decision): its owner endpoint, frozen contract field, route, `/api/settings` merge-skip, web client, registry shell guard and both browser guards all stay, the stored value is preserved and echoed with an explicit deprecation notice naming the context mode as the control that actually decides, and its getter is gone so nothing consults it. The shell guard also became PRECISE by INVERTED polarity: reaching the key or the owner endpoint is blocked unless the whole command line is demonstrably read-only inspection (per-segment command-head allowlist over the shared shell lexer), so a pure `grep OUROBOROS_SCOPE_REVIEW_FLOOR data/settings.json` read is no longer blocked while `python -c "httpx.request('POST', '…/api/owner/scope-review-floor', …)"` is refused — a marker list of write spellings failed OPEN on every spelling it did not enumerate. `OUROBOROS_SCOPE_REVIEW_DEGRADED` and the audited owner-opt-in degraded advisory scope review ARE removed — a DELIBERATE, DISCLOSED capability removal (CHECKLISTS #21); the replacement for installs with no ≥1M reviewer is `low` context mode. (4) An unbindable plan-review disposition now FAILS FAST with the claimed and stored fingerprints, the plan-text match, and the always-available escape, instead of being discarded and paying for a whole wave; a disposition may honestly bind the wave it NAMES only when the claimed fingerprint EQUALS the submitted envelope's (a review of `[a.py]` must not close a submission for `[a.py, b.py, c.py]` — agent-authored envelope drift is unbindable, not a warning); the binding fingerprint is a pure function of the agent's envelope (host-resolved `plan_class`/`context_level` excluded — stored fingerprints from earlier releases are invalidated once, harmlessly); per-slot component hashes are stored for `ENVELOPE_MISMATCH` diagnostics of that host-resolved drift; a slot the shared prompt cannot fit gets a free deterministic `preflight_oversize` record and a sub-quorum outcome is loud. (5) Diagnostics: four-way window wording (confirmed / owner-asserted / unknown-conservative / designated-default sentinel), honest `prompt_chars_source`, one aggregated `ladder_steps` field in the existing `context_manifest`, and the deleted floor guard takes a class of false blocks on pure reads with it. |
| 6.79.0 | 2026-07-25 | **feat: no-swarm means no swarm, planning scouts are admitted before they spend, and the GAIA adapter asks for honesty instead of lookups.** (1) `OUROBOROS_MAX_SUBAGENT_DEPTH=0` now truly disables delegation: `config._bounded_positive_int_setting` gained a `min_value` (0 for this setting only, 1 everywhere else) so a configured 0 is an owner choice instead of an "unset" value silently rewritten to the default 2 — every previous "no-swarm" run actually delegated two levels deep, and provenance for those rows is recorded, not re-litigated. Both depth gates already refuse at 0 and root tasks (depth 0 themselves) still run. (2) Consequence, tested rather than discovered later: `plan_task`'s planning scouts pass through the SAME delegation gate, so a depth-0 run gets no scouts and plan review completes on its existing `degraded_evidence` path — one typed refusal per intended scout, an explicit panel omission, no wedge and no second wave on resume. (3) A NEW scout wave is now admitted before launch — worker capacity, the shared `review_helpers.review_wave_budget_gate` (no second budget authority; it prices one opening round per scout, a deliberate lower bound), and a consumable window — while the recovery/collection path is deliberately NEVER gated, because those handoffs are already PAID and declining them would abandon spend instead of saving it. Each scout's contract deadline is bound to the window in which its handoff can still be consumed (the wave's shared cutoff minus the finalization grace and a margin, the reserve capped at a fraction of a short window) instead of inheriting the parent deadline verbatim; `_schedule_task` gained the deadline parameter it lacked, and a requested deadline can only TIGHTEN the inherited one. No third heartbeat predicate (settled oscillation). (4) GAIA gains `GAIA_EPISTEMIC_INSTRUCTION` beside the format and anti-leak constants: an adapter-only DISCLOSURE rule (say when a claim rests on something you did not verify) that explicitly does NOT ask for lookups of facts the model already knows, appended identically by all four solvers, stripped from traces before the leakage scan, wording-locked by tests, and disclosed in `gaia/METHODOLOGY.md`. Nothing changed in `prompts/SYSTEM.md`, no typed contract field, no finalization gate — a test pins that scope, and `DEVELOPMENT.md`'s bench-adapter rule gained an explicit carve-out for this instruction class. (5) Harbor readiness: `run_tb.py`/`harbor_installed_agent.py` stop assuming TB2.1. The dataset identity is threaded into the adapter, which resolves the per-task wall-clock cap from the exact `~/.cache/harbor/tasks/packages/<org>/<name>/<digest>` subtree — the org is not a constant (`terminal-bench`, `gaia` and `scale-ai` coexist in that cache, so the old hardcoded literal made every other dataset run deadline-blind) — with a name-only fallback that REFUSES on ambiguity rather than handing over a foreign dataset's cap; the submission subtree is derived from the dataset instead of a hardcoded `submissions/terminal-bench/2.1/`; `--base-job-config` deep-merges an upstream JobConfig UNDER our `agents[]` block (whose `name` must stay ours or the submission is permanently invalid); `--agent-env`/`--verifier-env` reach harbor's own `--ae`/`--ve` with their VALUES redacted out of every artifact THIS launcher writes (manifest `official_command`, `harbor_command.txt`, stdout — names only) — and the code's earlier claim that those values are "never written to the run root" is corrected, because it was false on the path where it matters most: harbor persists its OWN JobConfig into the job directory inside the public submission tree (`harbor/job.py` writes `config.model_dump_json(exclude_defaults=True)` to `<jobs-dir>/<job_name>/config.json`, and repeats the same env dicts in the job `lock.json` plus every trial's `config.json`/`lock.json`/`result.json`), where harbor's `templatize_sensitive_env` is keyed on the variable NAME only — measured on the installed 0.18.0, a name matching `KEY\|SECRET\|TOKEN\|PASSWORD\|CREDENTIAL\|AUTH` is written as `value[:4]+"****"+value[-3:]` (a partial disclosure of a live credential) and any other name, e.g. `MY_BEARER`, is written VERBATIM. So `scrub_submission_secrets.py` — still the single scrubber — gains `--env-passthrough NAME=VALUE`: the pairs handed to `--ae`/`--ve` are swept BY VALUE across the whole tree (harbor's config/lock/result files included, no filename special-case), harbor's own partial form is swept as its own needle, the existing independent zero-leftover verify pass covers both, and a value that cannot be swept safely (too short, not credential-shaped, malformed pair) ABORTS before any write rather than producing a maybe-scrubbed upload; the launcher warns with the key NAMES and records the typed `env_passthrough_persisted_by_harbor` manifest fact; and the in-container key preflight now reads the authoritative `/api/v1/key` `limit_remaining` instead of the `total_credits − total_usage` arithmetic that lies on a nearly exhausted key (an uncapped key is admitted, not refused). Frontier-Bench (Terminal-Bench's declared successor) is now RUNNABLE readiness rather than a deferred question, and deliberately adds NO `frontier_bench/` package: it is a harbor DATASET with a TB2.x-identical task shape, so it needs only the identity `frontier-bench/frontier-bench` (`FRONTIER_BENCH_DATASET`) travelling through the SAME seam TB2.1 uses — harbor's `--dataset` plus the adapter kwarg that selects the per-task cache subtree, which harbor 0.18.0 was verified to populate as `~/.cache/harbor/tasks/packages/frontier-bench/<task>/<digest>/task.toml`. The load-bearing correction is about the BACKEND: upstream develops and scores FB on Modal (`--env modal`), which reads like a hard requirement for a cloud sandbox, but a real FB task's oracle solution was measured at reward 1.0 in 69s on the LOCAL docker daemon through FB's own separate-environment verifier, so no cloud provider, credential or account is needed to score a run locally. Backend choice is therefore explicit and disclosed instead of implicit: `--harbor-env` reaches harbor's own `-e/--env` (emitted ONLY when set, so the published TB2.1 argv stays byte-identical), and the manifest plus the disclosure ledger now record `harbor_bin`, `harbor_version` and `harbor_env_effective` — the backend that actually ran, named even when the flag was omitted, with an un-interrogable binary recorded as a visibly-unknown empty version rather than an assumed one. `METHODOLOGY.md` gains the FB disclosure block: what was measured, that 4 of 74 tasks request a GPU and one of those 1 TB of storage, that per-task agent caps run a median 7200s against TB2.1's minutes, that harbor scores locally so a smoke needs no submission or upload, and that every FB `task.toml` carries a contamination canary GUID which must never be quoted into a public artifact; its stale `venv-hi` reference is corrected to the real `venv-fb`. No Frontier-Bench run was scored and no number is claimed. (6) GAIA and both TB launchers drop their v6.75.0 `require_clean=False` pins and run the shared clean-seed gate with a recorded `--allow-dirty-seed` escape, while deliberately adding NO runtime attestation (each sample/trial starts its own server from the checkout under test — there is no evolved volume to skew). No benchmark campaign was run for any of this. |
| 6.78.0 | 2026-07-25 | **feat: one writer and three states for task acceptance; receipts reconcile per verification; two transparency facts.** (1) The HOST is now the only writer of the acceptance verdict: the agent-called `task_acceptance_review` used to REPLACE the whole `acceptance_decision` dict (its `rejected`/`partial`/`deferred` vocabulary landing in `outcome_axes.review.acceptance_decision.status`), and now MERGES only its own `agent_disposition`/`agent_rationale`/`dissent_noted` into the host decision — a merge, not a fresh dict, because assigning one clobbered the host verdict even without the three keys. `obligation_dispositions` and the agent-side `partial` default are unchanged. (2) The host's seven decision tokens collapse, inside the single merge point `_set_acceptance_decision`, into `accepted \| revision_requested \| finalized_unaccepted` plus a typed `reason` taken from facts the host already had (`dialogue_status`, `pass_reason`, panel/degraded reasons, the pacing launch reason); an unknown status fails closed to `finalized_unaccepted` keeping its raw token as the reason, so no future writer can mint a fourth owner-facing state. **Disclosed narrowing:** the persisted/displayed token changes for terminal acceptances (`review_degraded`, `best_effort_open_obligations`, `finalized_after_capsule`, `review_failed`, `review_skipped_deadline_reserve` → `finalized_unaccepted` + reason), the distinction moves to the additive `reason` key in the projection, and historical task results keep their old tokens (passthrough, no normalizer). The REVIEWER's `PASS\|FAIL\|DEGRADED` vocabulary, prompt, `_contract_valid_actors`, the deliberate-DEGRADED capsule rail and the host's core-overflow DEGRADED are byte-unchanged — only host statuses collapsed. `derive_loop_outcome` now keys the deadline-reserve degradation on the status+reason PAIR (keying on the old raw status alone would have silently stopped degrading an eligible-but-skipped panel — a false green), pinned by a table-driven test. (3) A failed verification receipt is reconciled only by a later green carrying the SAME TYPED IDENTITY KEY — `criterion_id` if the receipt has one, else the CANONICAL `check` text PAIRED WITH THE `check_rendering` STAMP that says which writer produced the stored string (tokenized through the shared `shell_parse` seam, so spacing between tokens folds while a quoted argument's contents, a quoted token that merely spells like an operator, and the control operators do not; the renderer changed from `" ".join(argv)` to `shlex.join(argv)` in this very release, and without the stamp an old red and a new green from DIFFERENT argvs could render identically and falsely reconcile — receipts from different renderings are now never the same verification, an absent stamp reads `unversioned` and matches only other unversioned receipts), else (for the artifact-observation class, which runs no command) the observed `paths` set (de-duplicated and sorted, never whitespace-touched: a leading or trailing space is a legal filename byte) — kind AND value, never across kinds, so a chain of per-component fallbacks that was not transitive (`{c1,check}` = `{check}` = `{c2,check}` while c1 ≠ c2, which let ONE check-only green clear two distinct reds and made the outstanding set order-dependent) is replaced by an equivalence relation and an existing `criterion_id` becomes authoritative structurally; a receipt carrying NO key at all keeps the older any-later-green rule (nothing to protect: a malformed `artifact_observation` with no paths would otherwise mint an unclearable red), and the masked-pass path applies the same equality to the `criterion_id` key alone, falling back to ANY later clean grounding only for a masked receipt that names no criterion (its only text identity is the MASKED command, which the prescribed remediation — drop the masking pipe — necessarily changes, so a byte-identical clean re-run cannot exist), with a disclosed `expected_whitespace_normalized` flag plus the chosen `reconciliation_identity` threaded into both consumers (the acceptance `verification_summary` and the FIXED ledger receipt row) through ONE shared `receipt_identity_projection`: ONE canonical identity derivation (`receipt_canonical_identity`) feeds comparison, hashing, counting and projection alike, so the outstanding sets count IDENTITIES rather than rows and the carried paths, their omitted count and their hash describe one and the same set; it discloses every bound it applies (`paths_omitted` plus `paths_identity_sha256` of that canonical set, and the SSOT `truncate_review_artifact` for strings instead of a hand-rolled slice that could return MORE characters than it was given), and the acceptance summary now carries the UNRECONCILED RED's identity (`unreconciled_red_identity`) and not only the latest receipt's, because a later green of a DIFFERENT verification leaves an earlier red standing and a flag whose cause never reaches the reviewer is not reconstructible. **Disclosed narrowing:** a red re-run under a cosmetically different command (`pytest x.py` vs `pytest x.py -v`) no longer counts as reconciled, and neither does a green re-run that OMITS the `criterion_id` its red carried — the single key fails in the SAFE direction (strictly fewer reconciliations, so a red may stay open where the old chain cleared it, never the reverse) — so such a turn can see one extra ADVISORY nudge and an `unreconciled_red` flag in the acceptance evidence; the rule is advisory in both places and never a gate, the reviewer rules now say "never cleared by a green re-run of the same criterion/check" instead of "ignored its OWN red", and `criterion_id` is documented as the preferred identity (with the named exception written into the content-derived-identity anti-pattern section). (4) Transparency: one `tool_policy.format_capability_omissions()` replaces five divergent copies (two in `tools/tool_discovery.py`, three in `loop.py`) and renders the richest available detail, so a contract-disabled or credential-missing tool now shows its REAL names instead of `no detail`; and the acceptance reviewer receives a host-attested `retrieval` fact (native `web_search_sources`/`server_tool_use` folded at `add_usage`, mirrored into `llm_trace`, exposed in the evidence packet — counts plus at most 20 URLs of at most 200 chars, no titles or snippets), framed in the rules as factual context whose ABSENCE is not a deficiency and never shown to the agent. `outcomes.py` stays inside the 1600-line gate by moving the receipt/ledger projection helpers into the existing private `_outcome_receipts.py` seam and dropping two dead constants; `review_substrate.py` is untouched and no module is grandfathered. |
| 6.77.0 | 2026-07-25 | **fix: send-time prompt-cache policy has one home; direct-Anthropic prompt tokens are complete.** (1) Cache markers were placed by two per-builder copies (`_build_anthropic_tools`, `_build_remote_kwargs`) that could not see the whole request, and the ordering guard lost in `176567b` was gone: a 5m tools marker in front of a 1h review pack is a hard Anthropic 400 (a longer TTL must precede a shorter one). Both copies are deleted and the observational TTL reporter is replaced by one finalizer on the FULLY ASSEMBLED payload (`llm.LLMClient._normalize_payload_cache_ttl`, all five physical-send boundaries: both `chat_async` branches, `_chat_anthropic`, both `_chat_remote` branches) that walks breakpoints in real wire prefix order `tools -> system -> messages`, PROMOTES earlier existing breakpoints to `1h` when any later one declares `1h` (constructive, not a re-added assertion), marks the last tool schema only when the tools segment carries none, and on a >4-breakpoint payload keeps the four earliest governance anchors while dropping tail MARKERS — never content — with a disclosed `prompt_cache_breakpoints_reduced` usage field (Anthropic rejects >4 outright, so an assembly bug degrades the cache instead of failing a main-loop send; the loud builder-side `review_substrate.assert_cache_breakpoint_cap` is unchanged). Eligibility reuses the existing family authority `supports_message_cache_control` plus the route's provider/model, so direct OpenAI, OpenAI-compatible, Cloud.ru, GigaChat, unsupported OpenRouter families and Gemini (bare markers, never a `ttl` field) stay byte-identical, and caller-owned `messages`/`tools` are never mutated. (2) Direct-Anthropic usage now reports `prompt_tokens = input_tokens + cache_read_input_tokens + cache_creation_input_tokens`: Anthropic excludes cache reads/writes from `input_tokens`, while `pricing` subtracts cached+write from `prompt_tokens` (fresh input was clamped to 0 on cache-heavy calls), `cache_hit_rate` divides by it (could exceed 1.0), and the route calibration ratio measures it. **Ledger-semantics boundary:** `llm_round`/`llm_usage` rows for direct Anthropic before and after this release carry different input semantics (post-release rows are the complete input); the attempt ledger itself is unchanged because it reads the raw provider body. (3) The safety supervisor — the highest-frequency LIGHT lane, one call per tool call, measured at a 0.00 cache hit rate across 46 calls with roughly 85% of its input spent on the byte-stable `prompts/SAFETY.md` prefix — now DECLARES that prefix as a cached block at the caller (`safety._run_llm_check`, first attempt and JSON-repair retry, through the existing `review_helpers.cached_prompt_blocks` at the `1h` tier: the gap between checks is the runtime of the preceding tool and routinely outlives the 5-minute default). The finalizer in (1) may only ever add a marker to a tool schema, so this tool-free lane could not be cached any other way, and its general rule is unchanged — a tool-free payload whose caller declares nothing still gets no marker. Transport shape only: the prompt text, the model slot, the verdict parsing and the fail-closed semantics are byte-identical. |
| 6.74.5 | 2026-07-22 | **fix: subagents can read the skill payloads they audit; budget drift compares like with like.** (1) v6.70.0 granted read-only scouts read/list/search on `root=skill_payload`, but the path layer still resolved payloads against the child's isolated drive (`data/state/headless_tasks/<tid>/data`), which physically has no `skills/` tree — every scout was blinded with a bare "Directory not found" (2026-07-21 anime_studio audit swarm: three children produced zero payload reads and the parent died budget_exhausted doing everything alone). `resource_root_path` now resolves `skill_payload` against the canonical data root (new `canonical_data_root` helper: task_metadata `budget_drive_root` → ctx `budget_drive_root` → `drive_root`), so root tasks and isolated benchmark roots are unchanged while children read the real payload; the verb matrix is untouched — write/edit/review stay parent-only, path confinement and control-plane sidecar guards unchanged, native bucket stays out of the data-plane resolver. (2) `budget_drift_alert` compared the ALL-provider ledger delta against ONE OpenRouter key's usage delta, so real direct-provider spend (Anthropic advisory ~$98/day) latched the alert at ~88% while nothing was wrong. Drift now compares the OpenRouter-only settled ledger delta (`by_provider` from the attempt ledger; settled-only, reservations excluded) against the key's usage delta, rebaselines silently when the configured key changes mid-session (non-secret sha256 fingerprint) or when a pre-upgrade state lacks the new snapshot, suppresses the comparison honestly while the ledger is integrity-degraded, and `status_text` renders exactly the same deltas as the computation (the warning event keeps the all-provider delta as context). |
| 6.74.4 | 2026-07-21 | **feat: workspace-tree freeze directives (mitigation) + truthful ProgramBench submission contract.** Root cause (PB cmatsuoka__figlet smoke): an agent committed a compiling state, then broke the tree with one last uncommitted edit as the acceptance improvement loop hit its pass cap — and the harness ships the LIVE tree (`.git` dropped), so the verified commit protected nothing. All existing salvage machinery guards the answer TEXT only. Fix, prompt-only (P5) over existing channels (P7): the acceptance rails line marks the last admitted improvement pass (`passes_done+1 >= cap`, within cap>0) as FINAL, and EVERY workspace-delivery capsule (canonical `is_workspace_mode()` authority, attribute fallback for light contexts) carries the tree directive — a deadline or cost rail can end the loop between capsules — keep the tree VERIFIED (rebuild, verify, and commit if the task calls for a commit; revert unverified edits); the 10% deadline flush AND the ~80% cost wrap-up gain one shared commit-NEUTRAL tree sentence (acting self_worktree subagents cannot commit; a moved HEAD fails patch capture closed), byte-identical for non-workspace tasks; the ProgramBench instruction now states the true submission model — a source tarball from the CURRENT tree state (uncommitted edits DO ship; `.git`, root binaries and build/cache noise excluded), run `./compile.sh` one final time — replacing the false "fresh checkout" framing. Disclosed residual (mitigation, not closure): a forced tool-less exit — deadline grace or budget stop crossed inside one long round, with no pacing note or capsule in the terminal stretch — can still ship an unverified last edit; the structural verification-freshness seam is a filed follow-up pending an owner decision. |
| 6.74.3 | 2026-07-21 | **fix: Windows portability of one v6.74.0 guard test.** `test_genuine_repo_target_still_blocks` built its shell command via an f-string embedding a Windows path (backslashes mangled by shlex) and failed the 3-OS full matrix on windows-latest; the test now passes argv lists. No runtime code changes. |
| 6.74.2 | 2026-07-21 | **fix: CI portability of the two new GAIA sandbox-staging tests.** They imported `inspect_ai` directly — an optional benchmark dependency absent on CI runners — and failed quick-test with ModuleNotFoundError. The tests now inject a fake `inspect_ai.util.sandbox` module via monkeypatch, keeping the success-path coverage on every environment. No runtime code changes. |
| 6.74.1 | 2026-07-21 | **fix: CI lint gate — remove one unused test import.** The v6.74.0 tag CI failed on the deterministic ruff F-rule gate: `tests/test_devtools_benchmarks.py` carried an unused `types.SimpleNamespace` import added with the final GAIA staging tests. Import removed; no runtime code changes. Fix-forward release so the v6.74.x artifacts build (the published v6.74.0 tag is never re-tagged). |
Older releases are preserved in Git tags and GitHub releases. Older 6.x rows (including 6.76.0, 6.75.0, 6.74.0, 6.73.2, 6.73.1, 6.73.0, 6.72.0, 6.71.2, 6.71.1, 6.71.0, 6.70.0, 6.69.0, 6.68.0, 6.67.0, 6.66.0, 6.65.4, 6.65.3, 6.65.2, 6.65.1, 6.65.0, 6.64.3, 6.64.2, 6.64.1, 6.64.0, 6.63.0, 6.62.0, 6.61.4, 6.61.3, 6.61.1, 6.61.0, 6.60.0, 6.59.0, 6.58.0, 6.57.0, 6.56.0, 6.55.0, 6.54.4, 6.54.2, 6.54.1, 6.54.0, 6.53.4, 6.53.0, 6.51.0), the 5.2.0 through 5.33.0-rc.6 rows, and former `4.0.0` rows are rolled off to respect the P9 changelog cap; their full bodies remain at their git tags.

---

## License

[MIT License](LICENSE)

Created by [Anton Razzhigaev](https://t.me/abstractDL) & Andrew Kaznacheev
