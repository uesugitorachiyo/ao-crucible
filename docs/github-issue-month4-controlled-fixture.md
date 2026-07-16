# Month 4 Controlled GitHub Issue Fixture

This repository contains one controlled public fixture for the AO Stack
GitHub issue-to-draft-PR Month 4 qualification path.

Fixture:

- `examples/github-issue-fixtures/month4-controlled-bug-score-drift.json`

Purpose:

- Provide an operator-owned, non-security, deterministic bug report target.
- Exercise the issue URL intake, reproduction, isolated repair, verification,
  action-digest, and draft-PR path.
- Keep the bug inside fixture data rather than AO Crucible production behavior.

Reproduction command:

```sh
go run ./cmd/controlled-fixture-verifier --fixture examples/github-issue-fixtures/month4-controlled-bug-score-drift.json
```

Expected current result:

- The command exits non-zero while `reported_score` differs from
  `expected_score`.

Expected repair:

- Set `reported_score` to `100`.
- Set `bug_present` to `false`.
- Do not change denied actions, issue policy, release behavior, provider
  behavior, or repository authority boundaries.
