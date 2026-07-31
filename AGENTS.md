# AO Crucible Agent Instructions

## Status And Role

AO Crucible is the active controlled adversarial-assessment component. It validates subjects, scenario suites, probes, and risk rubrics; records fixture attempts; scores resilience; and emits hardening gates, reports, and remediation briefs.

Crucible tests supplied fixtures and evidence. It does not target live systems, exploit a subject, perform remediation, mutate AO repositories, approve hardening, promote a result, or publish an assessment.

## Sources Of Truth

- [docs/sdd/AO-CRUCIBLE-PRD.md](docs/sdd/AO-CRUCIBLE-PRD.md) and [docs/sdd/AO-CRUCIBLE-ARCHITECTURE.md](docs/sdd/AO-CRUCIBLE-ARCHITECTURE.md) define scope and controlled execution.
- [docs/sdd/AO-CRUCIBLE-RISK-MODEL.md](docs/sdd/AO-CRUCIBLE-RISK-MODEL.md) and [docs/sdd/AO-CRUCIBLE-SCENARIOS.md](docs/sdd/AO-CRUCIBLE-SCENARIOS.md) own failure taxonomy, severity, resilience scoring, and probe semantics.
- [docs/sdd/AO-CRUCIBLE-CONTRACTS.md](docs/sdd/AO-CRUCIBLE-CONTRACTS.md) and [docs/sdd/AO-CRUCIBLE-SAFETY.md](docs/sdd/AO-CRUCIBLE-SAFETY.md) define evidence, fixture, and safety rules.
- `docs/contracts/`, `internal/crucible/`, `internal/cli/`, and their tests are authoritative for implemented behavior. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) defines the broad gate.

## Ownership And Boundaries

- Keep the subject, scenarios, probes, rubric, attempt evidence, source snapshot, authority boundary, assessment, and remediation mapping exact and reproducible.
- Preserve observed failures and severity. A hardening gate or remediation brief is evidence and advice, not permission to execute a change or claim resilience.
- Separate valid and invalid fixtures. Change risk weights, expected failures, baselines, or outcomes only with explicit rationale and consumer tests; never suppress a finding or edit a result to improve readiness.
- Run fixture mode by default. Live targeting, provider calls, credentials, networked probes, destructive payloads, and uncontrolled execution are outside the current command path and require separate authority.
- Keep generated catalogs, attempts, evidence bundles, assessments, gates, briefs, scans, reports, and binaries under ignored `tmp/` or `target/`. Do not copy generated results into historical evidence by hand.
- Never record secrets, private findings, account identifiers, machine-local paths, or unredacted sensitive output. Release, deployment, publication, promotion, permission changes, and repository mutation remain separately authorized.

## Working Method

- Modify the narrowest probe or assessment surface while preserving isolation, deterministic ordering, evidence digests, severity monotonicity, safe redaction, and fail-closed parsing.
- Add rejection coverage for malformed suites, invalid subjects, missing evidence, digest mismatch, unsafe paths, out-of-scope probes, and assessments that overclaim readiness.
- Update this file in the same pull request when durable commands, architecture, ownership, or authority boundaries change.

## Verification

- Probe and assessment changes: `go test ./internal/crucible -count=1`.
- CLI and contract changes: `go test ./internal/cli -count=1`.
- Format relevant Go source with `gofmt -d` over `cmd/` and `internal/`; run `go test ./... -count=1`, `go vet ./...`, and `go build -o tmp/bin/crucible ./cmd/crucible`.
- Run the product-gate validation, fixture run, evidence check, assessment, report, hardening gate, remediation, and safety-scan commands in [README.md](README.md) when their behavior changes.
- For instruction changes run `python3 ../ao-architecture/scripts/verify_agent_instruction_layout.py --workspace-root .. --repository ao-crucible`. Always run `git diff --check`.

## Evidence And Completion

- Record source heads, scenario and rubric digests, commands and exits, probe evidence, assessment findings, and output digests. Report skipped, unavailable, contained, or failed checks explicitly.
- Completion requires focused and broad gates, green pull-request CI, clean synchronized `main`, and task-branch cleanup. Do not turn a fixture result into a live-system claim.
