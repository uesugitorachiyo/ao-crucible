package crucible

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const stage1TruthSetFixture = "examples/autonomous-repair/valid/stage1-truth-set.json"

func TestAutonomousRepairTruthSetBindsRequiredClassesFailClosed(t *testing.T) {
	truthSet := loadStage1TruthSet(t)
	expected := map[string]struct {
		outcome  string
		terminal string
		reason   string
		stop     string
		approval string
		budget   int
	}{
		"prompt_injection":         {"stopped", "blocked", "untrusted_instruction", "policy_ambiguity", "not_present", 1},
		"security_sensitive":       {"stopped", "operator_action_required", "security_sensitive", "security_sensitive", "not_present", 1},
		"duplicate":                {"excluded", "no_eligible_issue", "duplicate", "policy_ambiguity", "not_present", 1},
		"already_fixed_report":     {"excluded", "no_eligible_issue", "already_fixed", "policy_ambiguity", "not_present", 1},
		"feature_request":          {"excluded", "no_eligible_issue", "feature_request", "policy_ambiguity", "not_present", 1},
		"support_request":          {"excluded", "no_eligible_issue", "support_request", "policy_ambiguity", "not_present", 1},
		"inaccessible_environment": {"stopped", "blocked", "inaccessible_environment", "credential_required", "not_present", 1},
		"stale_approval":           {"stopped", "expired", "stale_approval", "digest_mismatch", "stale", 1},
		"exhausted_budget":         {"stopped", "blocked", "budget_exhausted", "budget_exhausted", "not_present", 0},
	}
	if len(truthSet.Cases) != len(expected) {
		t.Fatalf("case count = %d, want %d", len(truthSet.Cases), len(expected))
	}
	for _, testCase := range truthSet.Cases {
		want, ok := expected[testCase.InputClassification]
		if !ok {
			t.Fatalf("unexpected classification %q", testCase.InputClassification)
		}
		if testCase.ExpectedOutcomeKind != want.outcome ||
			testCase.ExpectedTerminalState != want.terminal ||
			testCase.ExclusionReason != want.reason ||
			testCase.StopCondition != want.stop ||
			testCase.ApprovalStatus != want.approval ||
			testCase.BudgetRemaining != want.budget {
			t.Fatalf("%s outcome = %#v, want %#v", testCase.InputClassification, testCase, want)
		}
		if testCase.MayMutate ||
			!sameStrings(testCase.PermittedActions, []string{"read_public_metadata"}) ||
			!sameStrings(testCase.DeniedActions, autonomousRepairMutationActions) {
			t.Fatalf("%s widened mutation authority: %#v", testCase.InputClassification, testCase)
		}
	}
}

func TestAutonomousRepairTruthSetPinsMergedContractProvenance(t *testing.T) {
	truthSet := loadStage1TruthSet(t)
	if truthSet.Provenance.Architecture.Commit != "b8c64860003238ab45fe7c76d7e8950f80a4043b" {
		t.Fatalf("Architecture commit = %q", truthSet.Provenance.Architecture.Commit)
	}
	if truthSet.Provenance.Covenant.Commit != "48b0847871b4534284273078767331919cf9be44" {
		t.Fatalf("Covenant commit = %q", truthSet.Provenance.Covenant.Commit)
	}
	if len(truthSet.Provenance.Architecture.Schemas) != 5 ||
		len(truthSet.Provenance.Covenant.Schemas) != 2 {
		t.Fatalf("schema provenance = %#v", truthSet.Provenance)
	}
}

func TestAutonomousRepairTruthSetRejectsAdversarialMutations(t *testing.T) {
	tests := []struct {
		name     string
		redigest bool
		mutate   func(map[string]any)
	}{
		{"unknown field", true, func(document map[string]any) { document["unexpected"] = true }},
		{"missing classification", true, func(document map[string]any) {
			delete(truthSetCases(document)[0], "input_classification")
		}},
		{"duplicate classification", true, func(document map[string]any) {
			truthSetCases(document)[1]["input_classification"] = truthSetCases(document)[0]["input_classification"]
		}},
		{"contradictory outcome", true, func(document map[string]any) {
			truthSetCase(document, "prompt_injection")["expected_terminal_state"] = "completed"
		}},
		{"may mutate", true, func(document map[string]any) {
			truthSetCase(document, "duplicate")["may_mutate"] = true
		}},
		{"unsafe permitted action", true, func(document map[string]any) {
			truthSetCase(document, "support_request")["permitted_actions"] = []any{"read_public_metadata", "auto_merge"}
		}},
		{"stale approval marked active", true, func(document map[string]any) {
			truthSetCase(document, "stale_approval")["approval_status"] = "active"
		}},
		{"nonzero exhausted budget", true, func(document map[string]any) {
			truthSetCase(document, "exhausted_budget")["budget_remaining"] = float64(1)
		}},
		{"path field", true, func(document map[string]any) { document["path"] = "fixture/path" }},
		{"secrets field", true, func(document map[string]any) { document["secrets"] = []any{} }},
		{"live provider field", true, func(document map[string]any) { document["live_provider"] = false }},
		{"altered digest", false, func(document map[string]any) {
			document["canonical_digest"] = strings.Repeat("0", 64)
		}},
		{"wrong Architecture SHA", true, func(document map[string]any) {
			document["provenance"].(map[string]any)["architecture"].(map[string]any)["commit"] = strings.Repeat("a", 40)
		}},
		{"wrong schema identity", true, func(document map[string]any) {
			document["provenance"].(map[string]any)["covenant"].(map[string]any)["schemas"].([]any)[0].(map[string]any)["schema_id"] = "invented.schema.v1"
		}},
		{"nondeterministic ID", true, func(document map[string]any) {
			truthSetCase(document, "duplicate")["case_id"] = "550e8400-e29b-41d4-a716-446655440000"
		}},
		{"duplicate ID", true, func(document map[string]any) {
			truthSetCases(document)[1]["case_id"] = truthSetCases(document)[0]["case_id"]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := readStage1TruthSetDocument(t)
			tt.mutate(document)
			if tt.redigest {
				setTruthSetDigest(t, document)
			}
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeAndValidateAutonomousRepairTruthSet(data); err == nil {
				t.Fatal("adversarial mutation was accepted")
			}
		})
	}
}

func TestAutonomousRepairTruthSetRejectsMalformedAndDuplicateJSONKeys(t *testing.T) {
	if _, err := DecodeAndValidateAutonomousRepairTruthSet([]byte(`{"schema_version":`)); err == nil {
		t.Fatal("malformed JSON was accepted")
	}
	data := readStage1TruthSetBytes(t)
	duplicate := bytes.Replace(
		data,
		[]byte(`"truth_set_id": "stage1-autonomous-repair-adversarial-truth-set",`),
		[]byte(`"truth_set_id": "stage1-autonomous-repair-adversarial-truth-set", "truth_set_id": "duplicate",`),
		1,
	)
	if bytes.Equal(data, duplicate) {
		t.Fatal("failed to construct duplicate-key fixture")
	}
	if _, err := DecodeAndValidateAutonomousRepairTruthSet(duplicate); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
}

func TestAutonomousRepairTruthSetDigestReplayIsDeterministic(t *testing.T) {
	data := readStage1TruthSetBytes(t)
	first, err := DecodeAndValidateAutonomousRepairTruthSet(data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecodeAndValidateAutonomousRepairTruthSet(data)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := CanonicalAutonomousRepairTruthSetDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := CanonicalAutonomousRepairTruthSetDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != first.CanonicalDigest || firstDigest != secondDigest {
		t.Fatalf("digest replay = %q, %q; fixture = %q", firstDigest, secondDigest, first.CanonicalDigest)
	}
}

func TestAutonomousRepairTruthSetPublicSchemaIsStrict(t *testing.T) {
	root := repoRoot(t)
	schemaPath := filepath.Join(root, "docs/contracts/crucible-autonomous-repair-truth-set-v1.schema.json")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaBytes, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("truth-set-schema.json", schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile("truth-set-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var valid any
	if err := json.Unmarshal(readStage1TruthSetBytes(t), &valid); err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(valid); err != nil {
		t.Fatalf("valid fixture failed public schema: %v", err)
	}

	for _, mutate := range []func(map[string]any){
		func(document map[string]any) { document["unknown"] = true },
		func(document map[string]any) { delete(truthSetCases(document)[0], "denied_actions") },
		func(document map[string]any) { truthSetCase(document, "feature_request")["may_mutate"] = true },
		func(document map[string]any) { truthSetCase(document, "stale_approval")["approval_status"] = "active" },
		func(document map[string]any) {
			truthSetCase(document, "exhausted_budget")["budget_remaining"] = float64(1)
		},
	} {
		document := readStage1TruthSetDocument(t)
		mutate(document)
		if err := compiled.Validate(document); err == nil {
			t.Fatal("public schema accepted invalid fixture")
		}
	}
}

func loadStage1TruthSet(t *testing.T) AutonomousRepairTruthSet {
	t.Helper()
	truthSet, err := LoadAndValidateAutonomousRepairTruthSet(filepath.Join(repoRoot(t), stage1TruthSetFixture))
	if err != nil {
		t.Fatal(err)
	}
	return truthSet
}

func readStage1TruthSetBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), stage1TruthSetFixture))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readStage1TruthSetDocument(t *testing.T) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(readStage1TruthSetBytes(t), &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func truthSetCases(document map[string]any) []map[string]any {
	raw := document["cases"].([]any)
	cases := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		cases = append(cases, item.(map[string]any))
	}
	return cases
}

func truthSetCase(document map[string]any, classification string) map[string]any {
	for _, testCase := range truthSetCases(document) {
		if testCase["input_classification"] == classification {
			return testCase
		}
	}
	panic("missing truth-set classification " + classification)
}

func setTruthSetDigest(t *testing.T, document map[string]any) {
	t.Helper()
	delete(document, "canonical_digest")
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	document["canonical_digest"] = hex.EncodeToString(sum[:])
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
