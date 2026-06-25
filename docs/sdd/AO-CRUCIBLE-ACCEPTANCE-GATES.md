# AO Crucible Acceptance Gates

## SDD Readiness Gate

The SDD documents score 100/100 only when:

- PRD defines product scope, users, goals, non-goals, AO stack relationships,
  and production readiness definition;
- architecture defines commands, packages, data flow, storage layout,
  integration boundaries, and error handling;
- contracts define schema families, required fields, valid fixtures, invalid
  fixtures, and validation rules;
- risk model defines 100-point resilience scoring, severity rules, penalties,
  blockers, and worked examples;
- scenario suite defines all ten canonical adversarial scenarios;
- safety document defines forbidden actions, secret detection, path detection,
  live-mode requirements, public artifact rules, and fail-closed behavior;
- implementation slices define future files, commands, tests, and acceptance
  checks;
- handoff prompt tells AO Forge or AO Foundry exactly how to implement slice by
  slice;
- `target/ao-crucible-plan.json` validates with AO2 SDD validation;
- placeholder scan finds no incomplete planning markers.

## Product Readiness Gate

AO Crucible v0.1 scores 100/100 only when the implemented repository passes:

```sh
go test ./...
go vet ./...
go build -o tmp/bin/crucible ./cmd/crucible
PATH="$PWD/tmp/bin:$PATH" crucible suite validate --suite examples/suites/valid/ao-crucible-v0.1.json
PATH="$PWD/tmp/bin:$PATH" crucible subject validate --subject examples/subjects/valid/ao-orchestration.json
PATH="$PWD/tmp/bin:$PATH" crucible run fixture --suite examples/suites/valid/ao-crucible-v0.1.json --subject examples/subjects/valid/ao-orchestration.json --out tmp/crucible-run
PATH="$PWD/tmp/bin:$PATH" crucible evidence validate --bundle tmp/crucible-run/evidence-bundle.json
PATH="$PWD/tmp/bin:$PATH" crucible assess --attempt tmp/crucible-run/attempt.json --rubric examples/rubrics/resilience-v0.1.json --out tmp/crucible-assessment.json
PATH="$PWD/tmp/bin:$PATH" crucible report render --assessment tmp/crucible-assessment.json --out tmp/crucible-report.md
PATH="$PWD/tmp/bin:$PATH" crucible gate hardening --assessment tmp/crucible-assessment.json --out tmp/crucible-hardening-gate.json
PATH="$PWD/tmp/bin:$PATH" crucible remediation brief --assessment tmp/crucible-assessment.json --out tmp/crucible-remediation-brief.json
PATH="$PWD/tmp/bin:$PATH" crucible safety scan --path README.md --out tmp/crucible-readme-scan.json
PATH="$PWD/tmp/bin:$PATH" crucible safety scan --path docs --out tmp/crucible-docs-scan.json
PATH="$PWD/tmp/bin:$PATH" crucible safety scan --path examples --out tmp/crucible-examples-scan.json
git diff --check
```

## Competitive Gate

AO Crucible is competitive only when it provides:

- deterministic fixture-mode adversarial scenarios;
- evidence-backed resilience scoring;
- critical blocker semantics that override aggregate score;
- public-safe remediation briefs;
- clean-clone reproducibility;
- explicit boundaries between read-only evidence import and repository mutation;
- a demo that shows a real AO orchestration candidate being blocked or promoted
  for understandable reasons.

## Public Safety Gate

Public safety passes only when durable files under `README.md`, `docs`,
`examples`, `cmd`, and `internal` contain no private prompts, secret-like
strings, local absolute paths, unredacted run evidence, or unsupported claims.

## Exit Condition For Autonomous Implementation

An autonomous AO Forge or AO Foundry run should stop when:

- all implementation slices are complete;
- product readiness gate passes from a clean clone;
- hardening gate emits `passed`;
- public safety scan passes;
- final response includes commands, results, readiness score, and remaining
  non-blocking future work.

If any critical blocker repeats three times with the same root cause, the run
must stop and report the blocker rather than continue cycling.
