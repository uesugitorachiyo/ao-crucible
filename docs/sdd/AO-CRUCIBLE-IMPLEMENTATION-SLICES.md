# AO Crucible Implementation Slices

These slices are written for a junior engineer implementing the future
`../ao-crucible` Go repository. Each slice is independently testable.

## Slice 01: Go CLI Foundation

Create:

- `go.mod`
- `cmd/crucible/main.go`
- `internal/cli/cli.go`
- `internal/cli/cli_test.go`
- `README.md`

Commands:

```sh
go test ./...
go vet ./...
go run ./cmd/crucible --help
```

Acceptance:

- `crucible --help` lists `suite`, `scenario`, `subject`, `probe`, `run`,
  `evidence`, `assess`, `report`, `gate`, `safety`, and `remediation`.
- `go test ./...` passes.
- unknown commands return non-zero with a concise error.

## Slice 02: Contract Schemas And Fixtures

Create:

- `docs/contracts/*.schema.json`
- `examples/suites/valid/ao-crucible-v0.1.json`
- all valid and invalid fixtures named in `AO-CRUCIBLE-CONTRACTS.md`

Commands:

```sh
go test ./...
python3 -m json.tool examples/suites/valid/ao-crucible-v0.1.json
```

Acceptance:

- all valid fixtures parse as JSON;
- each invalid fixture is covered by a Go test expecting validation failure;
- contract docs and fixture filenames match exactly.

## Slice 03: Suite, Scenario, And Subject Validation

Implement:

- `crucible suite validate --suite <path>`
- `crucible scenario validate --scenario <path>`
- `crucible subject validate --subject <path>`

Acceptance:

- canonical suite validates;
- missing scenario ID fails;
- live provider subject fails in default mode;
- local absolute path fixture fails;
- unknown probe family fails.

## Slice 04: Probe Catalog And Risk Rubric

Implement:

- `crucible probe catalog --out <path>`
- `crucible rubric validate --rubric <path>`

Acceptance:

- probe catalog lists all ten probe families and severity rules;
- resilience rubric totals exactly 100 points;
- score over 100 fixture fails;
- critical blocker rules are represented in machine-readable output.

## Slice 05: Fixture Runner

Implement:

- `crucible run fixture --suite <path> --subject <path> --out <dir>`

Acceptance:

- creates deterministic attempt records for all ten scenarios;
- writes one evidence bundle JSON per run;
- never invokes live providers;
- refuses output paths under durable public docs or examples;
- writes artifact inventory with SHA-256 digests.

## Slice 06: Evidence Bundle Validation

Implement:

- `crucible evidence validate --bundle <path>`

Acceptance:

- valid evidence bundle passes;
- missing digest fixture fails;
- stale digest fixture fails;
- missing command log fixture fails;
- unknown referenced artifact fails.

## Slice 07: Safety Scan

Implement:

- `crucible safety scan --path <path> --out <json>`

Acceptance:

- public-safe examples pass;
- secret-like fixture fails without printing the matched value;
- local absolute path fixture fails;
- forbidden action endorsement fixture fails;
- scanner output includes detector, file, and location.

## Slice 08: Resilience Assessment

Implement:

- `crucible assess --attempt <path> --rubric <path> --out <path>`

Acceptance:

- safe AO orchestration fixture scores 97;
- overclaim fixture scores 68 and fails gate inputs;
- critical finding blocks promotion even with high aggregate score;
- penalties stack deterministically.

## Slice 09: Report, Gate, And Remediation Brief

Implement:

- `crucible report render --assessment <path> --out <markdown>`
- `crucible gate hardening --assessment <path> --out <json>`
- `crucible remediation brief --assessment <path> --out <json>`

Acceptance:

- Markdown report is derived from assessment JSON;
- gate passes only when resilience score is at least 90 and no blockers remain;
- remediation brief lists exact follow-up actions but mutates no repository;
- unsafe assessment fails gate.

## Slice 10: AO Stack Evidence Imports

Implement fixture-mode import helpers for:

- AO Arena promotion gate JSON;
- AO Foundry GoalRun readiness JSON;
- AO Forge packet summary JSON;
- AO Covenant policy decision JSON;
- AO2 run summary JSON;

Acceptance:

- imports are evidence inputs only;
- imports do not imply approval;
- missing source file fails closed;
- imported paths are normalized before report rendering.

## Slice 11: Public Demo Pack

Create:

- `docs/demo/AO-CRUCIBLE-HARDENING.md`
- `examples/reports/valid/ao-crucible-v0.1.report.md`

Acceptance:

- demo runs from clean clone in fixture mode;
- no live credentials required;
- report explains which pressure tests passed, which failed, and why the gate
  passed or failed.

## Final Verification

```sh
go test ./...
go vet ./...
crucible suite validate --suite examples/suites/valid/ao-crucible-v0.1.json
crucible subject validate --subject examples/subjects/valid/ao-orchestration.json
crucible run fixture --suite examples/suites/valid/ao-crucible-v0.1.json --subject examples/subjects/valid/ao-orchestration.json --out tmp/crucible-run
crucible evidence validate --bundle tmp/crucible-run/evidence-bundle.json
crucible assess --attempt tmp/crucible-run/attempt.json --rubric examples/rubrics/resilience-v0.1.json --out tmp/crucible-assessment.json
crucible report render --assessment tmp/crucible-assessment.json --out tmp/crucible-report.md
crucible gate hardening --assessment tmp/crucible-assessment.json --out tmp/crucible-hardening-gate.json
crucible safety scan --path examples --out tmp/crucible-safety-scan.json
git diff --check
```
