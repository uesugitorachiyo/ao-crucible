# AO Crucible

AO Crucible is the adversarial hardening layer for the AO orchestration
framework. Where AO Arena measures whether one orchestration approach beats
another, AO Crucible tries to make an orchestration fail in controlled,
fixture-only conditions before that orchestration is trusted for public release
or autonomous overnight work.

The v0.1 product is a local-first Go CLI. It validates adversarial scenario
suites, runs deterministic fixture-mode probes, collects evidence, scores
resilience, renders hardening reports, emits promotion gates, scans public
artifacts, and creates remediation briefs that block unsafe or overclaimed AO
improvements.

Fixture mode is the only default v0.1 execution path. AO Crucible does not run
live providers, mutate sibling repositories, push, tag, release, upload, deploy,
or store credentials.

## Run

```sh
go test ./...
go vet ./...
go run ./cmd/crucible --help
```

Product gate commands from a clean checkout:

```sh
go build -o tmp/bin/crucible ./cmd/crucible
PATH="$PWD/tmp/bin:$PATH" crucible suite validate --suite examples/suites/valid/ao-crucible-v0.1.json
PATH="$PWD/tmp/bin:$PATH" crucible scenario validate --scenario examples/scenarios/valid/prompt-injection-instruction-conflict.json
PATH="$PWD/tmp/bin:$PATH" crucible subject validate --subject examples/subjects/valid/ao-orchestration.json
PATH="$PWD/tmp/bin:$PATH" crucible rubric validate --rubric examples/rubrics/resilience-v0.1.json
PATH="$PWD/tmp/bin:$PATH" crucible probe catalog --out tmp/crucible-probe-catalog.json
PATH="$PWD/tmp/bin:$PATH" crucible run fixture --suite examples/suites/valid/ao-crucible-v0.1.json --subject examples/subjects/valid/ao-orchestration.json --out tmp/crucible-run
PATH="$PWD/tmp/bin:$PATH" crucible evidence validate --bundle tmp/crucible-run/evidence-bundle.json
PATH="$PWD/tmp/bin:$PATH" crucible assess --attempt tmp/crucible-run/attempt.json --rubric examples/rubrics/resilience-v0.1.json --out tmp/crucible-assessment.json
PATH="$PWD/tmp/bin:$PATH" crucible report render --assessment tmp/crucible-assessment.json --out tmp/crucible-report.md
PATH="$PWD/tmp/bin:$PATH" crucible gate hardening --assessment tmp/crucible-assessment.json --out tmp/crucible-hardening-gate.json
PATH="$PWD/tmp/bin:$PATH" crucible remediation brief --assessment tmp/crucible-assessment.json --out tmp/crucible-remediation-brief.json
PATH="$PWD/tmp/bin:$PATH" crucible safety scan --path README.md --out tmp/crucible-readme-scan.json
PATH="$PWD/tmp/bin:$PATH" crucible safety scan --path docs --out tmp/crucible-docs-scan.json
PATH="$PWD/tmp/bin:$PATH" crucible safety scan --path examples --out tmp/crucible-safety-scan.json
git diff --check
```

## SDD Files

| File | Purpose |
| --- | --- |
| `docs/sdd/AO-CRUCIBLE-PRD.md` | Product requirements, users, scope, non-goals, success metrics. |
| `docs/sdd/AO-CRUCIBLE-ARCHITECTURE.md` | Planned CLI, packages, data flow, storage layout, integrations. |
| `docs/sdd/AO-CRUCIBLE-CONTRACTS.md` | JSON contracts, fixture names, validation rules. |
| `docs/sdd/AO-CRUCIBLE-RISK-MODEL.md` | Failure taxonomy, severity levels, resilience scoring formula. |
| `docs/sdd/AO-CRUCIBLE-SCENARIOS.md` | Canonical adversarial scenario suite and probe semantics. |
| `docs/sdd/AO-CRUCIBLE-SAFETY.md` | Public-safety, forbidden actions, live-run opt-in, fail-closed rules. |
| `docs/sdd/AO-CRUCIBLE-IMPLEMENTATION-SLICES.md` | Junior-engineer-ready implementation slices. |
| `docs/sdd/AO-CRUCIBLE-ACCEPTANCE-GATES.md` | 100/100 plan and product readiness gates. |
| `docs/sdd/AO-CRUCIBLE-SDD-HANDOFF.md` | Handoff prompt for AO Foundry or AO Forge. |
| `docs/sdd/AO-CRUCIBLE-PHASE-2-GAP-AUDIT.md` | Gaps discovered after the Slice 01-03 scaffold. |

## Planner Artifacts

The validated AO2 SDD plan lives at:

- `target/ao-crucible-plan.json`

The planner prompt lives at:

- `docs/sdd/AO-CRUCIBLE-SDD-PLANNER-PROMPT.md`

## Implementation Rule

Implementation follows the SDD slices in order and keeps every durable artifact
public-safe. Live provider mode remains blocked unless a later profile,
operator opt-in, command flag, scratch output path, and pre/post safety scans all
authorize it.

## Current Scaffold Status

The current implementation includes:

- CLI help and unknown-command failure;
- `suite validate`;
- `scenario validate`;
- `subject validate`;
- `rubric validate`;
- `probe catalog`;
- `run fixture`;
- `evidence validate`;
- `assess`;
- `report render`;
- `gate hardening`;
- `remediation brief`;
- `safety scan`;
- JSON inventory tests for durable contract, example, and planner artifacts;
- shared scratch output policy requiring generated outputs under `tmp/`;
- evidence bundle digest structs and SHA-256 validation helpers;
- AO stack evidence import helpers.

The next hardening step is hosted CI and public repository setup after git
initialization.
