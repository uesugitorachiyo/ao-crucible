# AO Crucible PRD

## Product Summary

AO Crucible is the adversarial hardening layer for the AO orchestration
framework. It subjects an AO orchestration candidate to deterministic,
fixture-mode failure pressure: prompt-injection attempts, policy-bypass probes,
secret-redaction traps, stale-evidence traps, stop-condition traps,
cross-repository boundary probes, branch-fragmentation probes, and
overclaim-detection probes.

AO Crucible exists because recursive system improvement needs more than a
scoreboard. AO Arena can say whether AO orchestration beat a baseline. AO
Crucible says whether the candidate survived pressure well enough to be trusted
for autonomous operation, public release, or self-improvement.

## Users

| User | Job |
| --- | --- |
| AO framework maintainer | Find hardening gaps before promoting a candidate orchestration. |
| Release reviewer | Inspect adversarial evidence behind a release or public-readiness claim. |
| Junior engineer | Implement the CLI and fixtures from exact SDD slices. |
| Operator | Run public-safe pressure tests without live credentials. |
| AO Foundry loop | Require Crucible hardening gates before proposing recursive changes. |
| AO Forge executor | Implement remediations from Crucible findings under governed GoalRun gates. |

## v0.1 Goals

1. Define adversarial scenario suites for AO orchestration candidates.
2. Validate subject profiles for bare prompts, AO orchestration prompts, and
   future AO stack components.
3. Run deterministic fixture-mode probes without live provider credentials.
4. Collect evidence for each scenario: input fixture, expected refusal or safe
   behavior, observed behavior, command logs, artifact inventory, safety scan,
   and verifier results.
5. Score candidate resilience using a deterministic 100-point rubric.
6. Render JSON and Markdown hardening reports.
7. Emit a hardening gate result that blocks promotion when critical failures,
   unsafe artifacts, missing evidence, or overclaims are detected.
8. Produce remediation briefs that AO Forge or AO Foundry can consume as
   follow-up work, without directly mutating sibling repositories.

## Non-Goals

- Do not run live model providers in default v0.1 paths.
- Do not execute real exploit payloads, network attacks, credential discovery,
  destructive filesystem actions, or repository mutations.
- Do not push, tag, release, upload, deploy, or mutate sibling repositories.
- Do not store secrets, tokens, private prompts, private evidence, or local
  absolute paths in durable artifacts.
- Do not replace AO Arena, AO Foundry, AO Forge, AO2, AO Covenant, AO Command,
  or ao2-control-plane.
- Do not claim safety from a passing score alone; promotion must require
  absence of critical failures and public-safety cleanliness.

## Success Metrics

AO Crucible v0.1 is successful when:

- ten canonical adversarial scenarios validate;
- fixture-mode runs are reproducible from a clean checkout;
- every resilience score can be recomputed from saved evidence;
- critical failures block the hardening gate even when aggregate score is high;
- redaction failures do not print secret-like values;
- local absolute paths are blocked from durable examples and reports;
- generated remediation briefs are actionable but do not perform the mutation;
- a junior engineer can implement every slice from the SDD documents without
  guessing.

## Relationship To The AO Stack

| Component | Crucible relationship |
| --- | --- |
| AO Arena | Arena measures comparative performance; Crucible pressure-tests the winner before promotion. |
| AO Foundry | Uses Crucible hardening gates before accepting self-improvement candidates. |
| AO Forge | Can implement remediation briefs emitted by Crucible under GoalRun controls. |
| AO2 | Supplies governed run evidence for later live modes and validates the SDD plan. |
| AO Covenant | Supplies policy, approval, redaction, and fail-closed concepts for Crucible gates. |
| AO Command | Can summarize Crucible hardening reports for operators. |
| ao2-control-plane | May store read-only hardening readback after explicit operator promotion. |

## Production Readiness Definition

The SDD documents are implementation-ready when they specify exact future files,
commands, schemas, fixtures, scoring formulas, adversarial scenarios, failure
cases, and verification gates. The product is production-ready when `go test
./...`, `go vet ./...`, suite validation, fixture runs, evidence validation,
resilience assessment, report rendering, safety scanning, hardening gating, and
clean-clone smoke commands all pass.
