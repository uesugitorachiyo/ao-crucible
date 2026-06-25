# AO Crucible Contracts

## Contract Families

| Contract | Planned schema path | Purpose |
| --- | --- | --- |
| Scenario suite | `docs/contracts/crucible-suite-v0.1.schema.json` | Lists scenario IDs, rubric, subject constraints, and fixture-mode rules. |
| Scenario | `docs/contracts/crucible-scenario-v0.1.schema.json` | Defines one adversarial probe, expected safe behavior, severity, and evidence needs. |
| Probe catalog | `docs/contracts/crucible-probe-catalog-v0.1.schema.json` | Defines probe families and severity mapping. |
| Subject profile | `docs/contracts/crucible-subject-v0.1.schema.json` | Describes the orchestration candidate under test. |
| Attempt record | `docs/contracts/crucible-attempt-v0.1.schema.json` | Records deterministic observed behavior for each scenario. |
| Evidence bundle | `docs/contracts/crucible-evidence-bundle-v0.1.schema.json` | Lists artifacts, digests, command logs, and safety scan references. |
| Risk rubric | `docs/contracts/crucible-risk-rubric-v0.1.schema.json` | Defines scoring categories, penalties, and blocker rules. |
| Assessment | `docs/contracts/crucible-assessment-v0.1.schema.json` | Stores score, findings, remediations, and gate inputs. |
| Hardening gate | `docs/contracts/crucible-hardening-gate-v0.1.schema.json` | Emits pass or fail promotion decision. |
| Remediation brief | `docs/contracts/crucible-remediation-brief-v0.1.schema.json` | Describes follow-up work without performing it. |

## Common Required Fields

Every JSON contract includes:

- `schema_version`
- `id`
- `created_at_utc`
- `source`
- `trust_boundary`

Every durable contract that references another file includes:

- relative path only;
- SHA-256 digest for referenced evidence artifacts;
- schema version of the referenced artifact;
- role of the referenced artifact, such as `input`, `observed`, `scan`,
  `assessment`, or `gate`.

## Evidence Bundle Fields

The v0.1 scaffold defines this compact evidence bundle shape:

- `schema_version`: `ao.crucible.evidence-bundle.v0.1`;
- `bundle_id`: stable evidence bundle identifier;
- `artifacts`: list of evidence artifacts.

Each artifact includes:

- `path`: normalized path to the artifact;
- `role`: artifact role, such as `attempt`, `scenario`, `scan`, or
  `assessment`;
- `schema_version`: schema version of the referenced artifact;
- `sha256`: SHA-256 digest of the referenced artifact bytes;
- `redacted`: boolean stating whether the artifact is safe to include in public
  reports.

Digest validation fails closed when the artifact is missing or the computed
SHA-256 does not match the recorded digest.

## Scenario Required Fields

Each scenario includes:

- `scenario_id`
- `title`
- `probe_family`
- `severity`
- `fixture_input`
- `expected_safe_behavior`
- `forbidden_behavior`
- `evidence_requirements`
- `deterministic_outcome`
- `stop_condition`

Allowed severities:

- `critical`
- `high`
- `medium`
- `low`

Allowed probe families:

- `prompt_injection`
- `secret_redaction`
- `forbidden_action`
- `local_path_leak`
- `evidence_integrity`
- `stop_condition`
- `cross_repo_boundary`
- `approval_bypass`
- `branch_hygiene`
- `overclaim_detection`

## Subject Profile Required Fields

Subject profiles include:

- `subject_id`
- `display_name`
- `subject_type`
- `fixture_mode_supported`
- `declared_capabilities`
- `declared_forbidden_actions`
- `expected_outputs`
- `public_safety_profile`

Allowed subject types:

- `bare_prompt`
- `ao_orchestration`
- `ao_component`
- `release_candidate`

## Valid Fixtures

Planned valid fixtures:

- `examples/suites/valid/ao-crucible-v0.1.json`
- `examples/scenarios/valid/prompt-injection-instruction-conflict.json`
- `examples/scenarios/valid/secret-redaction-trap.json`
- `examples/scenarios/valid/forbidden-release-action.json`
- `examples/scenarios/valid/local-path-public-artifact.json`
- `examples/scenarios/valid/stale-evidence-overclaim.json`
- `examples/scenarios/valid/stop-condition-loop.json`
- `examples/scenarios/valid/cross-repo-mutation-boundary.json`
- `examples/scenarios/valid/approval-bypass-spoof.json`
- `examples/scenarios/valid/branch-fragmentation.json`
- `examples/scenarios/valid/flaky-test-evidence-spoof.json`
- `examples/subjects/valid/ao-orchestration.json`
- `examples/rubrics/resilience-v0.1.json`

## Invalid Fixtures

Planned invalid fixtures:

- `examples/suites/invalid/missing-scenario-id.json`
- `examples/suites/invalid/live-mode-default.json`
- `examples/scenarios/invalid/critical-without-forbidden-behavior.json`
- `examples/scenarios/invalid/secret-value-in-fixture.json`
- `examples/scenarios/invalid/local-absolute-path.json`
- `examples/scenarios/invalid/missing-stop-condition.json`
- `examples/scenarios/invalid/unknown-probe-family.json`
- `examples/subjects/invalid/live-provider-enabled.json`
- `examples/subjects/invalid/declares-forbidden-release-action.json`
- `examples/rubrics/invalid/score-over-100.json`

## Validation Rules

- Reject unknown schema versions.
- Reject absolute paths in durable fixtures.
- Reject secret-like values in durable fixtures and reports.
- Reject live provider settings unless a future live profile explicitly allows
  them.
- Reject any fixture whose declared expected behavior permits pushing, tagging,
  releasing, uploading, deploying, or mutating sibling repositories.
- Reject missing evidence requirements for critical and high scenarios.
- Reject hardening gates that pass when critical findings are present.
- Reject generated output paths outside `tmp/` for v0.1 commands that write
  files.
