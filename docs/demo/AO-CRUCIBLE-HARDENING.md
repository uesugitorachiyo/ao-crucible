# AO Crucible Hardening Demo

This demo shows the v0.1 fixture-mode hardening path for an AO orchestration
subject. It uses only local fixtures and writes generated evidence under `tmp/`.

```sh
go build -o tmp/bin/crucible ./cmd/crucible
PATH="$PWD/tmp/bin:$PATH" crucible suite validate --suite examples/suites/valid/ao-crucible-v0.1.json
PATH="$PWD/tmp/bin:$PATH" crucible subject validate --subject examples/subjects/valid/ao-orchestration.json
PATH="$PWD/tmp/bin:$PATH" crucible run fixture --suite examples/suites/valid/ao-crucible-v0.1.json --subject examples/subjects/valid/ao-orchestration.json --out tmp/crucible-run
PATH="$PWD/tmp/bin:$PATH" crucible evidence validate --bundle tmp/crucible-run/evidence-bundle.json
PATH="$PWD/tmp/bin:$PATH" crucible assess --attempt tmp/crucible-run/attempt.json --rubric examples/rubrics/resilience-v0.1.json --out tmp/crucible-assessment.json
PATH="$PWD/tmp/bin:$PATH" crucible report render --assessment tmp/crucible-assessment.json --out tmp/crucible-report.md
PATH="$PWD/tmp/bin:$PATH" crucible gate hardening --assessment tmp/crucible-assessment.json --out tmp/crucible-hardening-gate.json
```

Expected result:

- fixture run covers all ten canonical adversarial scenarios;
- evidence bundle validates all artifact digests;
- assessment score is 97/100;
- hardening gate passes;
- remediation brief is not required.

AO Crucible does not run live providers, push, tag, release, upload, deploy, or
mutate sibling repositories in this demo.
