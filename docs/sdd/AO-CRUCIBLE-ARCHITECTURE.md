# AO Crucible Architecture

## Planned Product Shape

AO Crucible v0.1 is a local-first Go CLI named `crucible`. It uses fixture-mode
adversarial scenarios to test whether an orchestration subject handles safety,
evidence, stop conditions, and repository boundaries correctly.

The CLI writes all generated outputs under caller-provided scratch paths such as
`tmp/crucible-run`. Durable examples, docs, schemas, and fixtures must never
contain private data, local absolute paths, or secret-like strings.

## Planned Commands

| Command | Purpose |
| --- | --- |
| `crucible suite validate --suite <path>` | Validate an adversarial scenario suite. |
| `crucible scenario validate --scenario <path>` | Validate one scenario fixture. |
| `crucible subject validate --subject <path>` | Validate the candidate profile under test. |
| `crucible probe catalog --out <path>` | Emit the built-in probe catalog and severity taxonomy. |
| `crucible run fixture --suite <path> --subject <path> --out <dir>` | Produce deterministic attempt and evidence files. |
| `crucible evidence validate --bundle <path>` | Validate evidence completeness and digest references. |
| `crucible assess --attempt <path> --rubric <path> --out <path>` | Score resilience and emit findings. |
| `crucible report render --assessment <path> --out <markdown>` | Render a Markdown hardening report from JSON. |
| `crucible gate hardening --assessment <path> --out <path>` | Emit pass or fail promotion gate. |
| `crucible safety scan --path <path> --out <json>` | Scan durable artifacts for forbidden strings and paths. |
| `crucible remediation brief --assessment <path> --out <path>` | Produce an actionable remediation brief without mutating repos. |

## Planned Packages

| Package | Responsibility |
| --- | --- |
| `internal/cli` | Parse commands, dispatch subcommands, return deterministic exit codes. |
| `internal/contracts` | Decode JSON, enforce schema-like semantic validation, normalize paths. |
| `internal/scenario` | Load suites, scenario fixtures, expected outcomes, and probe metadata. |
| `internal/subject` | Validate candidate profiles and fixture-mode behavior declarations. |
| `internal/runner` | Execute deterministic fixture runs without live providers. |
| `internal/evidence` | Build evidence bundles, compute SHA-256 digests, validate references. |
| `internal/safety` | Detect forbidden actions, secret-like strings, and local absolute paths. |
| `internal/risk` | Apply severity taxonomy, resilience scoring, penalties, and gate blockers. |
| `internal/report` | Render JSON-derived Markdown reports and remediation briefs. |
| `internal/gate` | Emit hardening gate results from assessments. |

## Data Flow

1. Operator validates a suite and subject profile.
2. Fixture runner loads scenario inputs and expected safe behaviors.
3. Runner writes deterministic attempt records and evidence bundles.
4. Evidence validator checks references, digests, command logs, and artifact
   inventory.
5. Safety scanner checks examples, evidence, and reports.
6. Assessor computes resilience score, critical findings, and remediation items.
7. Reporter renders a human-readable hardening report from the assessment JSON.
8. Gate emits `passed` only when score, critical finding, evidence, and safety
   requirements are all satisfied.

## Storage Layout

Planned durable files:

- `docs/contracts/crucible-*.schema.json`
- `examples/suites/valid/ao-crucible-v0.1.json`
- `examples/scenarios/valid/*.json`
- `examples/scenarios/invalid/*.json`
- `examples/subjects/valid/ao-orchestration.json`
- `examples/subjects/invalid/*.json`
- `examples/rubrics/resilience-v0.1.json`
- `docs/demo/AO-CRUCIBLE-HARDENING.md`

Planned generated scratch files:

- `tmp/crucible-run/attempt.json`
- `tmp/crucible-run/evidence-bundle.json`
- `tmp/crucible-assessment.json`
- `tmp/crucible-report.md`
- `tmp/crucible-hardening-gate.json`
- `tmp/crucible-safety-scan.json`

## Integration Boundaries

AO Crucible v0.1 imports evidence from sibling tools only as fixture files. It
does not shell into sibling repositories, run live providers, update branches,
or write control-plane state. Later live modes require explicit operator
approval, scratch output paths, and pre/post safety scans.

## Error Handling

All commands fail closed. Validation errors include file path, contract family,
field name, and reason. Redaction errors must report the detector name and
location without printing the matched secret-like value. Any critical finding,
missing evidence digest, unsafe path, forbidden action, or unsupported live mode
returns a non-zero exit code.

## Phase 2 Scaffold Boundary

The scaffold now implements `suite validate`, `scenario validate`, `subject
validate`, `rubric validate`, and `probe catalog`. Commands that write generated
artifacts use a shared output policy: v0.1 generated outputs must be under
`tmp/`, while durable public paths such as `README.md`, `docs`, `examples`,
`cmd`, and `internal` are rejected for generated output.

Evidence bundle support is defined as a digest model, not a fixture runner yet.
The next architectural step is to make `crucible run fixture` produce attempt
records and evidence bundles using the existing SHA-256 artifact model.
