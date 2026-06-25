# AO Crucible Safety

## Default Safety Posture

AO Crucible v0.1 is fixture-only and fail-closed. It must not run live model
providers, execute real exploit payloads, mutate repositories, push, tag,
release, upload, deploy, or discover credentials.

## Forbidden Actions

The following actions are forbidden in default paths:

- pushing to any remote;
- creating or deleting tags;
- publishing releases or packages;
- uploading artifacts outside local scratch paths;
- deploying services;
- mutating sibling AO repositories;
- reading private credential stores;
- printing secret-like fixture values;
- writing local absolute paths to durable public artifacts;
- opening network connections for adversarial tests.

## Secret-Like Detectors

The scanner blocks durable outputs that match common credential shapes,
including:

- bearer token patterns;
- API key labels;
- private key blocks;
- GitHub token-like strings;
- cloud access key-like strings;
- password assignment patterns;
- synthetic fixture secret markers.

When a detector fires, output reports detector name, file, and JSON pointer or
line location. It does not print the matched value.

## Path Detectors

The scanner blocks durable examples and reports containing:

- Unix absolute home paths;
- macOS user paths;
- Windows drive-letter absolute paths;
- Windows UNC paths;
- temporary machine-specific paths.

Generated scratch evidence may contain local paths only when the artifact is
inside `tmp/`, excluded from durable examples, and redacted before report
rendering.

## Live Mode Requirements

Live mode is outside v0.1 default behavior. A later live mode requires:

- explicit command flag;
- subject profile allowing live mode;
- operator approval artifact;
- scratch output path;
- pre-run safety scan;
- post-run safety scan;
- hardening gate that records live mode as non-public evidence unless redacted.

## Public Artifact Rules

Durable files under `README.md`, `docs`, `examples`, `internal`, and `cmd` must
be public-safe. The safety scan must fail if these paths contain secret-like
strings, local absolute paths, unredacted private prompts, or command text that
endorses forbidden actions.

## Fail-Closed Rules

Any uncertainty about safety state results in failure. Missing scanner output,
unknown schema version, missing digest, missing subject profile, unsupported
probe family, invalid approval, or unrecognized live-mode flag blocks the gate.
