package crucible

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const stage5GovernanceAssuranceFixture = "examples/autonomous-repair/valid/stage5-governance-assurance.json"

func TestAutonomousRepairGovernanceAssuranceCoversRequiredOutcomes(t *testing.T) {
	suite := loadStage5GovernanceAssurance(t)
	required := []string{
		"sole-auto-merge-default-off",
		"sole-auto-merge-opted-in",
		"team-independent-exact-head",
		"team-same-vendor-reviewer",
		"team-stale-approval-head",
		"team-no-human-codeowner",
		"external-create-fork-branch",
		"external-reuse-fork-branch",
		"external-create-draft",
		"external-reuse-exact-draft",
		"external-mismatched-draft",
		"external-merge-denied",
		"unknown-draft-only",
		"unknown-merge-denied",
		"protected-path-denied",
		"failed-check-denied",
		"action-digest-mismatch",
		"expired-approval",
		"fork-identity-mismatch",
		"branch-head-mismatch",
		"force-update-denied",
		"upstream-push-denied",
		"issue-mutation-denied",
		"ready-transition-denied",
		"review-denied",
		"merge-denied",
		"team-open-ready-pr",
		"sole-open-ready-pr",
		"team-automated-reviewer-word",
		"team-bot-reviewer",
		"team-ao-prefix-reviewer",
		"team-codex-prefix-reviewer",
		"draft-fork-prerequisite-absent",
		"draft-fork-prerequisite-mismatch",
		"draft-branch-prerequisite-absent",
		"draft-branch-prerequisite-mismatch",
		"draft-lookup-ambiguous",
		"draft-conflict-exact-reread",
		"draft-conflict-missing-reread",
		"draft-conflict-identity-drift",
		"draft-conflict-ambiguous-reread",
		"draft-post-create-readback-drift",
		"fork-post-create-readback-drift",
		"branch-post-push-readback-drift",
		"expiry-before-fork-write",
		"expiry-before-branch-write",
		"expiry-before-draft-write",
	}
	if len(suite.Cases) != len(required) {
		t.Fatalf("case count = %d, want %d", len(suite.Cases), len(required))
	}
	for index, caseID := range required {
		testCase := suite.Cases[index]
		if testCase.CaseID != caseID {
			t.Fatalf("case[%d] = %q, want %q", index, testCase.CaseID, caseID)
		}
		derived := EvaluateAutonomousRepairGovernanceAssurance(testCase.Input)
		if derived != testCase.Expected {
			t.Fatalf("%s derived = %#v, expected %#v", caseID, derived, testCase.Expected)
		}
	}
}

func TestAutonomousRepairGovernanceAssurancePinsMergedContracts(t *testing.T) {
	suite := loadStage5GovernanceAssurance(t)
	if suite.Provenance.Architecture.Commit != "8e6f247b800b60c520b4e967f7553974a20ec2f8" ||
		suite.Provenance.Covenant.Commit != "561c167c57199913d4e2fa2692c21da68a2ecae6" ||
		suite.Provenance.AO2.Commit != "627c53f952bae5a638ce25ed934a81d01527a9f1" {
		t.Fatalf("merged contract provenance = %#v", suite.Provenance)
	}
	if suite.Provenance.Architecture.SourceSHA256 != "60bd07fa4e02d38f0321aa138bb53ca3f89e44499621a7e0369065bca88889ae" ||
		suite.Provenance.Architecture.SemanticsSHA256 != "2c6835289c508cd2954df545f93a1262c0616de87917bb1f749488376087b9b4" {
		t.Fatalf("Architecture digest provenance = %#v", suite.Provenance.Architecture)
	}
}

func TestAutonomousRepairGovernanceAssuranceRejectsRedigestedContradictions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"widen external merge", func(d map[string]any) {
			governanceAssuranceCase(d, "external-merge-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"widen unknown merge", func(d map[string]any) {
			governanceAssuranceCase(d, "unknown-merge-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"accept stale team head", func(d map[string]any) {
			governanceAssuranceCase(d, "team-stale-approval-head")["expected"].(map[string]any)["authorized"] = true
		}},
		{"accept same vendor", func(d map[string]any) {
			governanceAssuranceCase(d, "team-same-vendor-reviewer")["expected"].(map[string]any)["authorized"] = true
		}},
		{"accept missing human codeowner", func(d map[string]any) {
			governanceAssuranceCase(d, "team-no-human-codeowner")["expected"].(map[string]any)["authorized"] = true
		}},
		{"increase duplicate draft writes", func(d map[string]any) {
			governanceAssuranceCase(d, "external-reuse-exact-draft")["expected"].(map[string]any)["write_count"] = float64(1)
		}},
		{"allow force update", func(d map[string]any) {
			governanceAssuranceCase(d, "force-update-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"allow upstream push", func(d map[string]any) {
			governanceAssuranceCase(d, "upstream-push-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"allow issue mutation", func(d map[string]any) {
			governanceAssuranceCase(d, "issue-mutation-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"allow ready transition", func(d map[string]any) {
			governanceAssuranceCase(d, "ready-transition-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"allow review", func(d map[string]any) {
			governanceAssuranceCase(d, "review-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"allow merge", func(d map[string]any) {
			governanceAssuranceCase(d, "merge-denied")["expected"].(map[string]any)["authorized"] = true
		}},
		{"accept ambiguous draft lookup", func(d map[string]any) {
			governanceAssuranceCase(d, "draft-lookup-ambiguous")["expected"].(map[string]any)["authorized"] = true
		}},
		{"accept failed conflict reread", func(d map[string]any) {
			governanceAssuranceCase(d, "draft-conflict-missing-reread")["expected"].(map[string]any)["authorized"] = true
		}},
		{"accept post create drift", func(d map[string]any) {
			governanceAssuranceCase(d, "draft-post-create-readback-drift")["expected"].(map[string]any)["authorized"] = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := readStage5GovernanceAssuranceDocument(t)
			tt.mutate(document)
			setGovernanceAssuranceDigest(t, document)
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeAndValidateAutonomousRepairGovernanceAssurance(data); err == nil {
				t.Fatal("accepted redigested governance contradiction")
			}
		})
	}
}

func TestAutonomousRepairGovernanceAssuranceRejectsMissingUnknownAndDuplicateFields(t *testing.T) {
	document := readStage5GovernanceAssuranceDocument(t)
	delete(document, "safety_boundary")
	setGovernanceAssuranceDigest(t, document)
	missing, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndValidateAutonomousRepairGovernanceAssurance(missing); err == nil {
		t.Fatal("accepted missing safety boundary")
	}

	document = readStage5GovernanceAssuranceDocument(t)
	document["unexpected"] = true
	setGovernanceAssuranceDigest(t, document)
	unknown, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndValidateAutonomousRepairGovernanceAssurance(unknown); err == nil {
		t.Fatal("accepted unknown field")
	}

	duplicate := []byte(`{"schema_version":"ao.crucible.autonomous-repair-governance-assurance.v1","schema_version":"duplicate"}`)
	if _, err := DecodeAndValidateAutonomousRepairGovernanceAssurance(duplicate); err == nil {
		t.Fatal("accepted duplicate field")
	}
}

func TestAutonomousRepairGovernanceAssuranceRequiresEverySafetyField(t *testing.T) {
	for _, field := range []string{
		"mode", "live_provider_used", "network_used", "credentials_used",
		"github_mutation", "sibling_repo_mutation",
	} {
		t.Run(field, func(t *testing.T) {
			document := readStage5GovernanceAssuranceDocument(t)
			delete(document["safety_boundary"].(map[string]any), field)
			setGovernanceAssuranceDigest(t, document)
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeAndValidateAutonomousRepairGovernanceAssurance(data); err == nil {
				t.Fatal("accepted missing safety field")
			}
		})
	}
}

func TestAutonomousRepairGovernanceAssuranceRejectsRedigestedInputSubstitution(t *testing.T) {
	document := readStage5GovernanceAssuranceDocument(t)
	testCase := governanceAssuranceCase(document, "draft-fork-prerequisite-mismatch")
	testCase["input"].(map[string]any)["fork_state"] = "exact"
	testCase["expected"] = map[string]any{
		"authorized":     true,
		"reason_code":    "external_draft_only",
		"write_count":    float64(1),
		"terminal_state": "authorized",
	}
	setGovernanceAssuranceInputDigest(t, testCase)
	setGovernanceAssuranceDigest(t, document)
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndValidateAutonomousRepairGovernanceAssurance(data); err == nil {
		t.Fatal("accepted redigested required-case input substitution")
	}
}

func TestAutonomousRepairGovernanceAssuranceDigestReplays(t *testing.T) {
	first := loadStage5GovernanceAssurance(t)
	second := loadStage5GovernanceAssurance(t)
	firstDigest, err := CanonicalAutonomousRepairGovernanceAssuranceDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := CanonicalAutonomousRepairGovernanceAssuranceDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != first.CanonicalDigest || firstDigest != secondDigest {
		t.Fatalf("digest replay = %q, %q; fixture = %q", firstDigest, secondDigest, first.CanonicalDigest)
	}
}

func TestAutonomousRepairGovernanceAssurancePublicSchemaIsStrict(t *testing.T) {
	root := repoRoot(t)
	schemaBytes, err := os.ReadFile(filepath.Join(
		root,
		"docs/contracts/crucible-autonomous-repair-governance-assurance-v1.schema.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaBytes, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("governance-assurance-schema.json", schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("governance-assurance-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := readStage5GovernanceAssuranceDocument(t)
	if err := compiled.Validate(valid); err != nil {
		t.Fatalf("valid fixture failed public schema: %v", err)
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["unknown"] = true },
		func(d map[string]any) { delete(governanceAssuranceCase(d, "external-merge-denied"), "expected") },
		func(d map[string]any) {
			governanceAssuranceCase(d, "external-merge-denied")["input"].(map[string]any)["repository_class"] = "other"
		},
		func(d map[string]any) {
			governanceAssuranceCase(d, "external-merge-denied")["expected"].(map[string]any)["write_count"] = float64(4)
		},
	} {
		document := readStage5GovernanceAssuranceDocument(t)
		mutate(document)
		if err := compiled.Validate(document); err == nil {
			t.Fatal("public schema accepted invalid governance assurance fixture")
		}
	}
}

func loadStage5GovernanceAssurance(t *testing.T) AutonomousRepairGovernanceAssurance {
	t.Helper()
	suite, err := LoadAndValidateAutonomousRepairGovernanceAssurance(filepath.Join(
		repoRoot(t),
		stage5GovernanceAssuranceFixture,
	))
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

func readStage5GovernanceAssuranceDocument(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), stage5GovernanceAssuranceFixture))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func governanceAssuranceCase(document map[string]any, caseID string) map[string]any {
	for _, value := range document["cases"].([]any) {
		testCase := value.(map[string]any)
		if testCase["case_id"] == caseID {
			return testCase
		}
	}
	panic("missing governance assurance case " + caseID)
}

func setGovernanceAssuranceDigest(t *testing.T, document map[string]any) {
	t.Helper()
	delete(document, "canonical_digest")
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	document["canonical_digest"] = hex.EncodeToString(sum[:])
}

func setGovernanceAssuranceInputDigest(t *testing.T, testCase map[string]any) {
	t.Helper()
	data, err := json.Marshal(testCase["input"])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	testCase["input_sha256"] = hex.EncodeToString(sum[:])
}
