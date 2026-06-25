# AO Crucible SDD Handoff

Use this prompt after the SDD documents are reviewed.

```text
You are implementing AO Crucible v0.1 from the approved SDD documents.

Repository to create:
./ao-crucible

Source SDD documents:
./ao-crucible

Goal:
Build AO Crucible as the adversarial hardening layer for the AO orchestration
framework. The v0.1 product validates adversarial scenario suites, runs
fixture-mode pressure tests against orchestration subjects, collects evidence,
scores resilience, renders hardening reports, emits hardening gates, and creates
remediation briefs without mutating sibling repositories.

Required constraints:
- Start with fixture mode only.
- Do not run live providers.
- Do not execute real exploit payloads.
- Do not push, tag, release, upload, deploy, or mutate sibling repositories.
- Do not store secrets or local absolute paths in durable examples.
- Implement slice by slice from AO-CRUCIBLE-IMPLEMENTATION-SLICES.md.
- Add failing tests before each implementation slice.
- After each slice, run focused tests and update evidence.
- Stop when AO-CRUCIBLE-ACCEPTANCE-GATES.md product 100/100 gate passes.

First commands:
- inspect the SDD documents;
- create the Go CLI foundation;
- add contract and fixture validation tests before implementation logic;
- run `go test ./...`, `go vet ./...`, and `git diff --check`.

Final response must include:
- slices completed;
- files changed;
- verification commands and results;
- current production-readiness score;
- hardening gate result;
- remaining blocking next actions, if any.
```

## Implementation Readiness Verdict

The plan is ready to implement only when:

- `target/ao-crucible-plan.json` validates with AO2 SDD validation;
- all SDD docs contain concrete requirements rather than placeholders;
- acceptance gates define exact commands;
- the handoff prompt above needs no extra context.
