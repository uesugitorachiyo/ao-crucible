# AO Crucible

AO Crucible runs controlled adversarial scenarios and failure probes against an AO subject. It validates scenarios and rubrics, records probe attempts, assesses resilience, and produces remediation briefs. Use it when a workflow or execution result needs structured failure testing before operators rely on it. Its current command path uses supplied fixtures and evidence rather than targeting live systems.

## How it fits in AO

- **Primary responsibility:** Adversarial probes and controlled failure testing.
- **Inputs:** Subjects, scenario suites, risk rubrics, probe definitions, and recorded evidence.
- **Outputs:** Probe catalogs, attempts, assessments, hardening results, reports, and remediation briefs.
- **Upstream:** AO2 runs or other recorded subjects.
- **Downstream:** AO Sentinel and AO Promoter.

See the
[AO Architecture guide](https://github.com/uesugitorachiyo/ao-architecture)
and the
[AO Crucible component page](https://github.com/uesugitorachiyo/ao-architecture/blob/main/components/ao-crucible.md)
for the cross-repository flow.

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

## License

AO Crucible is licensed under `Apache-2.0`. See `LICENSE`.
