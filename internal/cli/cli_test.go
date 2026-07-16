package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHelpListsCommandFamilies(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run(--help) exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	for _, want := range []string{
		"suite validate",
		"scenario validate",
		"subject validate",
		"probe catalog",
		"run fixture",
		"evidence validate",
		"assess",
		"report render",
		"gate hardening",
		"safety scan",
		"remediation brief",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help output missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestUnknownCommandFails(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"explode"}, &stdout, &stderr)

	if code == 0 {
		t.Fatalf("Run(unknown) exit code = 0, want non-zero")
	}
	if !strings.Contains(stderr.String(), `unknown command "explode"`) {
		t.Fatalf("stderr = %q, want unknown command", stderr.String())
	}
}

func TestRubricValidateCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"rubric", "validate", "--rubric", "../../examples/rubrics/resilience-v0.1.json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("rubric validate exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rubric valid") {
		t.Fatalf("stdout = %q, want rubric valid", stdout.String())
	}
}

func TestProbeCatalogCommandWritesCatalog(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	out := filepath.Join(repoRoot(t), "tmp", "probe-catalog-test.json")

	code := Run([]string{"probe", "catalog", "--out", out}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("probe catalog exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "probe catalog written") {
		t.Fatalf("stdout = %q, want probe catalog written", stdout.String())
	}
}

func TestProductionGateCommandChain(t *testing.T) {
	root := repoRoot(t)
	outDir := filepath.Join(root, "tmp", "cli-production-gate")
	_ = os.RemoveAll(outDir)

	commands := [][]string{
		{"run", "fixture", "--suite", filepath.Join(root, "examples/suites/valid/ao-crucible-v0.1.json"), "--subject", filepath.Join(root, "examples/subjects/valid/ao-orchestration.json"), "--out", outDir},
		{"evidence", "validate", "--bundle", filepath.Join(outDir, "evidence-bundle.json")},
		{"assess", "--attempt", filepath.Join(outDir, "attempt.json"), "--rubric", filepath.Join(root, "examples/rubrics/resilience-v0.1.json"), "--out", filepath.Join(outDir, "assessment.json")},
		{"report", "render", "--assessment", filepath.Join(outDir, "assessment.json"), "--out", filepath.Join(outDir, "report.md")},
		{"gate", "hardening", "--assessment", filepath.Join(outDir, "assessment.json"), "--out", filepath.Join(outDir, "hardening-gate.json")},
		{"remediation", "brief", "--assessment", filepath.Join(outDir, "assessment.json"), "--out", filepath.Join(outDir, "remediation-brief.json")},
		{"safety", "scan", "--path", filepath.Join(root, "examples"), "--out", filepath.Join(outDir, "examples-scan.json")},
	}

	for _, args := range commands {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("Run(%v) exit code = %d, want 0; stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestProducesCrucibleFailureInjectionToPromoterAssuranceVector(t *testing.T) {
	root := repoRoot(t)
	vectorPath := filepath.Join(root, "examples", "compatibility", "crucible-failure-injection-to-promoter-assurance-input-v0.1.json")
	body, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]any
	if err := json.Unmarshal(body, &vector); err != nil {
		t.Fatal(err)
	}
	if vector["schema_version"] != "ao.compatibility.crucible-failure-injection-to-promoter-assurance-input-vector.v1" ||
		vector["edge"] != "ao-crucible.failure_injection_result -> ao-promoter.assurance_input" {
		t.Fatalf("unexpected Crucible compatibility vector identity: %#v", vector)
	}
	result := vector["crucible_failure_injection_result"].(map[string]any)
	if result["schema_version"] != "ao.crucible.failure-injection-result.v0.1" ||
		result["status"] != "passed" ||
		result["critical_failures"] != float64(0) {
		t.Fatalf("unexpected Crucible failure-injection result: %#v", result)
	}
	expected := vector["expected_promoter_assurance_input"].(map[string]any)
	if expected["schema_version"] != "ao.promoter.assurance-input.v1" ||
		expected["source_result_schema"] != result["schema_version"] ||
		expected["assurance_status"] != "accepted" {
		t.Fatalf("unexpected Promoter expectation: %#v", expected)
	}
	boundaries := vector["authority_boundaries"].(map[string]any)
	for _, key := range []string{"promotion_requested", "promotion_granted", "safe_to_execute", "executes_work", "mutates_repositories", "calls_providers", "releases_or_deploys"} {
		if boundaries[key] != false {
			t.Fatalf("Crucible vector boundary %s = %#v, want false", key, boundaries[key])
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
