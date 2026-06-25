# AO Crucible Phase 2 SDD Gap Audit

## Context

This audit was written after implementing the thin Slice 01-03 scaffold:

- Go module and CLI foundation;
- `suite validate`, `scenario validate`, and `subject validate`;
- contract schema placeholders;
- canonical v0.1 suite fixture;
- ten valid scenario fixtures;
- first invalid suite, scenario, subject, and rubric fixtures;
- focused tests for help output, unknown commands, canonical suite validation,
  scenario validation failures, and live-provider subject rejection.

The scaffold confirms the product shape is workable. Phase 2 should tighten the
spec before building runner, evidence, safety, scoring, report, gate, and
remediation commands.

## Confirmed Decisions

AO Crucible should stay fixture-only by default. The CLI skeleton should keep
future commands visible in help output while returning non-zero for commands not
implemented past Slice 03.

The first schema version names are:

- `ao.crucible.suite.v0.1`
- `ao.crucible.scenario.v0.1`
- `ao.crucible.subject.v0.1`
- `ao.crucible.risk-rubric.v0.1`

The first module path is:

- `github.com/ao-foundry/ao-crucible`

The first validation package boundary is:

- `internal/crucible` for contracts and semantic validators;
- `internal/cli` for command dispatch only.

## Phase 2 Gaps

### Gap 01: Schema Validation Depth

Current scaffold uses Go semantic validators and minimal JSON Schema files.
Phase 2 must decide whether v0.1 requires full JSON Schema validation in Go or
keeps JSON Schema as public contract documentation while Go validators enforce
runtime semantics.

Recommended decision: keep Go semantic validation as the runtime source of
truth in v0.1, but add tests that every fixture's `schema_version` matches its
contract family and every schema file is valid JSON.

### Gap 02: Invalid Fixture Safety

Invalid fixtures need to express unsafe conditions without causing durable
public-safety scans to leak real secrets or real local paths. The scaffold uses
sentinel strings such as `LOCAL_ABSOLUTE_PATH_FIXTURE` and
`SECRET_VALUE_FIXTURE`.

Recommended decision: formalize sentinel fixtures in the safety SDD and teach
the future scanner to treat these sentinel strings as unsafe test inputs without
printing them in reports.

### Gap 03: Subject Capability Semantics

The subject validator currently blocks live provider usage, sibling mutation,
and credential storage. It does not yet decide whether a subject that declares
`release` as a capability should fail validation or merely fail a scenario.

Recommended decision: subject validation should reject release, push, tag,
upload, and deploy capabilities in default fixture mode unless the subject also
declares them in `declared_forbidden_actions`.

### Gap 04: Rubric Validator

The scaffold includes a valid rubric and an invalid score-over-100 fixture, but
there is no `crucible rubric validate` command yet.

Recommended decision: Slice 04 should add a rubric validator before probe
catalog generation. The validator should require category totals to equal 100,
require critical-blocker semantics, and reject unknown categories.

### Gap 05: Evidence Bundle Digest Model

The SDD names SHA-256 evidence references, but the scaffold has not defined the
exact evidence bundle shape used by fixture runs.

Recommended decision: define a compact evidence bundle with artifact path,
artifact role, SHA-256 digest, schema version, and redaction status. Do this
before implementing `crucible run fixture`.

### Gap 06: Output Path Policy

The SDD requires generated outputs to live under scratch paths, but the scaffold
has no reusable output path policy yet.

Recommended decision: add one shared helper that rejects output paths under
`README.md`, `docs`, `examples`, `cmd`, and `internal`, while allowing `tmp/`.

### Gap 07: Gate Input Semantics

The hardening gate currently has a clear policy in prose, but the assessment JSON
shape is not precise enough to implement without interpretation.

Recommended decision: before Slice 08, define `critical_findings`,
`high_findings`, `score`, `evidence_status`, `safety_status`,
`report_source_status`, and `live_mode_used` as explicit assessment fields.

## Recommended Phase 2 Slice Order

1. Add fixture/schema inventory tests for every JSON file.
2. Implement `crucible rubric validate`.
3. Implement `crucible probe catalog`.
4. Add shared output path policy.
5. Define evidence bundle struct and digest helpers.
6. Implement `crucible run fixture`.
7. Implement `crucible evidence validate`.
8. Implement `crucible safety scan`.

## Completed Phase 2 Scaffold Work

The first five Phase 2 actions are complete:

- fixture/schema inventory tests parse durable JSON files and count schema
  versions;
- `crucible rubric validate` accepts the 100-point rubric and rejects the
  score-over-100 fixture;
- `crucible probe catalog --out tmp/<file>` writes the ten-family probe catalog;
- shared output path policy allows `tmp/` and rejects durable public paths;
- evidence bundle structs and SHA-256 digest validation helpers are defined.

## Completed Later Work

The later production pipeline work now includes:

- `crucible run fixture`;
- `crucible evidence validate`;
- `crucible safety scan`;
- `crucible assess`;
- `crucible report render`;
- `crucible gate hardening`;
- `crucible remediation brief`;
- AO stack evidence import helpers;
- public demo/report artifacts.

## Phase 2 Stop Condition

Stop Phase 2 planning when:

- hosted CI and public release setup are ready to start;
- any new hardening work is tracked as a post-v0.1 production operations task,
  not a missing SDD requirement.
