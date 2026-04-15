# SnykrAI

An AI-powered security automation pipeline that continuously monitors your GitHub organization via Snyk, generates vulnerability fixes using Claude or Gemini, runs them through a multi-stage verification pipeline (build → test → Snyk re-scan), and opens draft PRs — all without human intervention in the loop.

---

## What it does

SnykrAI connects your Snyk organization to your GitHub repositories and automates the full remediation lifecycle:

1. **Fetch** — Pull open vulnerabilities from Snyk for all monitored repos
2. **Classify** — Distinguish direct upgrades from transitive overrides, apply SLA scoring
3. **Cascade Analysis** — Identify org-owned upstream packages whose upgrade would cascade fixes to multiple downstream repos
4. **LLM Fix** — Send manifest + issues to Claude or Gemini; get back a structured fix plan
5. **Install** — Apply the fix and run `npm install` / `mvn install` / `pip install` etc.
6. **Verify** — Re-run `snyk test` to confirm issue count dropped
7. **Build** — Run the ecosystem build command to catch regressions
8. **Test** — Run the test suite; rollback if tests fail
9. **Commit + Push** — Scan the diff for secrets before committing
10. **Draft PR** — Open a detailed draft PR with LLM reasoning, dep chains, risk level, and verification results

---

## Key features

- **Multi-ecosystem** — npm, Maven, Gradle, pip, Go modules, NuGet, CocoaPods, RubyGems
- **Multi-LLM** — Anthropic Claude (primary) + Google Gemini (fallback), configurable per-run
- **Cascade analysis** — Maps transitive dep chains to find org-owned packages whose upstream fix would cascade to multiple repos; prioritizes upstream fixes before override band-aids
- **Strategy system** — `conservative` (direct deps only) vs `aggressive` (transitive overrides), with a mandatory `override_rationale` decision record for audit trail
- **Breaking change analysis** — Fetches changelogs from npm/PyPI/GitHub releases; asks LLM if the upgrade will break existing code
- **SLA scoring** — Severity-weighted scoring with time-to-breach multipliers to prioritize which repos to fix first
- **Verified PRs** — Every PR is backed by: build pass + test pass + Snyk re-scan confirmation
- **Secret scanning** — Scans the git diff before every commit; blocks commits that contain leaked credentials
- **Slack integration** — `/snykr fix REPO` slash command triggers a single-repo fix run; run reports are posted to a channel
- **SAST auto-ignore** — Code analysis triage: LLM classifies Snyk Code findings as false positive / true positive / needs review; auto-ignores validated FPs via the Snyk Policies API

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          run.py / orchestrator                  │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────────────┐ │
│  │  SnykClient  │   │  OrgAnalyzer │   │    LLMClient        │ │
│  │  (Snyk API)  │   │  (cascade)   │   │  Claude + Gemini    │ │
│  └──────┬───────┘   └──────┬───────┘   └──────────┬──────────┘ │
│         │                  │                       │            │
│         └──────────────────┼───────────────────────┘           │
│                            ▼                                    │
│                    ┌───────────────┐                            │
│                    │   SnykFixer   │  per-repo fix pipeline     │
│                    │   (10 phases) │                            │
│                    └───────┬───────┘                            │
│                            │                                    │
│              ┌─────────────┼─────────────┐                      │
│              ▼             ▼             ▼                      │
│         ecosystem      GitOps        SecretScanner              │
│         handlers       (clone,        (pre-commit               │
│         (npm/mvn/       commit,        diff scan)               │
│          pip/go/        PR)                                     │
│          nuget)                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Getting started

### Prerequisites

- Python 3.11+
- [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) (`snyk` on PATH)
- [GitHub CLI](https://cli.github.com/) (`gh` on PATH, authenticated)
- A Snyk organization with repos already imported
- An Anthropic API key and/or Google Gemini API key

### Setup

```bash
git clone https://github.com/AniketDev7/snykrai
cd snykrai
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
```

### Configure repos

Edit `config.yaml` to add your repos. Every repo needs at minimum:

```yaml
repos:
  - name: "my-service"
    repo: "your-org/my-service"
    ecosystem: "npm"
    default_branch: "main"
    strategy: "conservative"
    visibility: "public"
```

Set `GIT_ORG` in your `.env` (or environment) to your GitHub org name — used for cascade analysis to identify org-owned packages in dep chains.

### Run

```bash
# Dry-run a single repo (fetch issues + LLM suggestions, no changes)
python run.py dry-run my-service

# Fix a single repo
python run.py fix my-service

# Fix a single repo with strategy override
python run.py fix my-service --strategy aggressive

# Full org scan (all repos in config.yaml, up to max_repos_per_run)
python run.py scan

# Fix a specific repo via orchestrator
python run.py scan --target my-service

# Show org-wide issue counts and status
python run.py status

# Triage SAST/code analysis findings with AI
python run.py scan-code my-service --auto-ignore
```

---

## Config reference

### Strategy guide

| Strategy | When to use | What it does |
|----------|------------|--------------|
| `conservative` | Published libraries, public SDKs, packages with downstream consumers | Only upgrades direct dependencies with a known `fixed_in` version. Transitive vulns are reported in the PR body but not patched. |
| `aggressive` | Internal tools, CLIs, private repos with no downstream consumers | Also pins transitive dependencies using ecosystem-native overrides (`npm overrides`, Maven `dependencyManagement`, pip constraints, Go `replace`). Requires `override_rationale`. |

### override_rationale (required for aggressive + transitive_overrides)

```yaml
override_rationale:
  decided_by: "your-handle"
  decided_on: "2026-01-01"
  trigger: "upstream_delay"       # upstream_delay | no_upstream_fix | security_critical
  revisit_after: "2026-07-01"     # check if upstream has caught up by this date
  reason: >
    Free-form explanation of why transitive overrides are acceptable here.
  public_facing: false
  has_tests: true
```

---

## PR format

Every PR opened by SnykrAI includes:

- **Cascade impact** — if this is an upstream fix that unblocks downstream repos
- **Verification** — `[x] Build passes`, `[x] Tests pass`, `[x] Snyk re-scan`
- **Risk level** — patch / minor / major based on semver diff
- **Direct upgrades table** — package, from, to, CVE, LLM reasoning
- **Transitive overrides section** — dep chain visualization, org-owned upstream packages
- **Breaking change analysis** — LLM assessment of whether the upgrade will break existing code (fetches changelog from npm/PyPI/GitHub)
- **Upstream fix recommendations** — if an org-owned package is the root cause in the dep chain

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token |
| `SNYK_ORG_ID` | Yes | Snyk organization UUID |
| `GIT_TOKEN` | Yes | GitHub PAT (repo + workflow scopes) |
| `GIT_USER` | Yes | GitHub username |
| `GIT_ORG` | Yes | GitHub organization name |
| `ANTHROPIC_API_KEY` | One of these | Anthropic API key for Claude |
| `GEMINI_API_KEY` | One of these | Google API key for Gemini |
| `SLACK_BOT_TOKEN` | No | Slack bot token for notifications |
| `SLACK_CHANNEL_ID` | No | Channel ID to post reports to |
| `SLACK_SIGNING_SECRET` | No | Slack signing secret (for slash command verification) |

---

## Running tests

```bash
pytest tests/ -v
```

Tests are grouped by module and use mocks to avoid hitting live APIs. The fixture data in `tests/fixtures/` provides real-shaped API responses.

---

## License

MIT
