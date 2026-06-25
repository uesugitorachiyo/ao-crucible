# AO Crucible SDD Planner Prompt

Use this prompt when asking an SDD planner to generate or improve the AO
Crucible plan.

```text
Create an `ao2.sdd-plan.v1` plan for AO Crucible.

Context:
- AO Crucible is the adversarial hardening layer for the AO orchestration
  framework.
- AO Arena measures comparative performance; AO Crucible tests whether the
  candidate survives adversarial pressure before promotion.
- The target repository path is the local `ao-crucible` repository root.
- The v0.1 implementation must be a local-first Go CLI.
- Fixture mode is the only default execution mode.
- The plan must not require live providers, network attacks, credential access,
  repository mutation, push, tag, release, upload, or deploy.

Required SDD outputs:
- PRD
- architecture
- contracts
- risk model
- adversarial scenarios
- safety model
- implementation slices
- acceptance gates
- handoff prompt
- AO2-valid plan JSON

The plan must be concrete enough that a junior engineer can implement the Go CLI
without inventing command semantics, schema families, fixture names, scoring
rules, safety rules, or final verification commands.
```
