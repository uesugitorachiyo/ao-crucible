package crucible

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCanonicalSuiteValidates(t *testing.T) {
	root := repoRoot(t)

	suite, err := LoadAndValidateSuite(filepath.Join(root, "examples/suites/valid/ao-crucible-v0.1.json"))

	if err != nil {
		t.Fatalf("LoadAndValidateSuite returned error: %v", err)
	}
	if suite.SuiteID != "ao-crucible-v0.1" {
		t.Fatalf("suite ID = %q, want ao-crucible-v0.1", suite.SuiteID)
	}
	if len(suite.Scenarios) != 10 {
		t.Fatalf("scenario count = %d, want 10", len(suite.Scenarios))
	}
}

func TestScenarioValidationRejectsMissingStopCondition(t *testing.T) {
	root := repoRoot(t)

	err := ValidateScenario(filepath.Join(root, "examples/scenarios/invalid/missing-stop-condition.json"))

	if err == nil {
		t.Fatalf("ValidateScenario accepted scenario without stop condition")
	}
	if !strings.Contains(err.Error(), "stop condition") {
		t.Fatalf("error = %v, want stop condition", err)
	}
}

func TestScenarioValidationRejectsUnknownProbeFamily(t *testing.T) {
	root := repoRoot(t)

	err := ValidateScenario(filepath.Join(root, "examples/scenarios/invalid/unknown-probe-family.json"))

	if err == nil {
		t.Fatalf("ValidateScenario accepted unknown probe family")
	}
	if !strings.Contains(err.Error(), "probe family") {
		t.Fatalf("error = %v, want probe family", err)
	}
}

func TestScenarioValidationRejectsLocalAbsolutePath(t *testing.T) {
	root := repoRoot(t)

	err := ValidateScenario(filepath.Join(root, "examples/scenarios/invalid/local-absolute-path.json"))

	if err == nil {
		t.Fatalf("ValidateScenario accepted local absolute path fixture")
	}
	if !strings.Contains(err.Error(), "local absolute path") {
		t.Fatalf("error = %v, want local absolute path", err)
	}
}

func TestSubjectValidationRejectsLiveProviderInDefaultMode(t *testing.T) {
	root := repoRoot(t)

	_, err := LoadAndValidateSubject(filepath.Join(root, "examples/subjects/invalid/live-provider-enabled.json"))

	if err == nil {
		t.Fatalf("LoadAndValidateSubject accepted live provider subject")
	}
	if !strings.Contains(err.Error(), "live provider") {
		t.Fatalf("error = %v, want live provider", err)
	}
}

func TestJSONInventoryValidatesAllDurableJSON(t *testing.T) {
	root := repoRoot(t)

	inventory, err := ValidateJSONInventory(root)

	if err != nil {
		t.Fatalf("ValidateJSONInventory returned error: %v", err)
	}
	if inventory.FileCount < 30 {
		t.Fatalf("inventory file count = %d, want at least 30", inventory.FileCount)
	}
	if inventory.SchemaVersions["ao.crucible.suite.v0.1"] == 0 {
		t.Fatalf("inventory missing suite schema version: %#v", inventory.SchemaVersions)
	}
}

func TestRubricValidationRequiresTotalOf100(t *testing.T) {
	root := repoRoot(t)

	rubric, err := LoadAndValidateRubric(filepath.Join(root, "examples/rubrics/resilience-v0.1.json"))
	if err != nil {
		t.Fatalf("LoadAndValidateRubric valid fixture returned error: %v", err)
	}
	if rubric.TotalPoints != 100 {
		t.Fatalf("rubric total = %d, want 100", rubric.TotalPoints)
	}

	_, err = LoadAndValidateRubric(filepath.Join(root, "examples/rubrics/invalid/score-over-100.json"))
	if err == nil {
		t.Fatalf("LoadAndValidateRubric accepted score-over-100 fixture")
	}
	if !strings.Contains(err.Error(), "100") {
		t.Fatalf("error = %v, want 100-point failure", err)
	}
}

func TestProbeCatalogListsAllProbeFamilies(t *testing.T) {
	catalog := BuildProbeCatalog()

	if catalog.SchemaVersion != "ao.crucible.probe-catalog.v0.1" {
		t.Fatalf("schema version = %q, want probe catalog v0.1", catalog.SchemaVersion)
	}
	if len(catalog.Probes) != 10 {
		t.Fatalf("probe count = %d, want 10", len(catalog.Probes))
	}
	if catalog.Probes[0].Family == "" || catalog.Probes[0].DefaultSeverity == "" {
		t.Fatalf("first probe is incomplete: %#v", catalog.Probes[0])
	}
}

func TestOutputPathPolicyAllowsTmpAndRejectsDurablePaths(t *testing.T) {
	if err := ValidateScratchOutputPath("tmp/crucible-run/evidence-bundle.json"); err != nil {
		t.Fatalf("tmp output rejected: %v", err)
	}

	for _, path := range []string{
		"README.md",
		"docs/generated.json",
		"examples/generated.json",
		"cmd/generated.json",
		"internal/generated.json",
	} {
		if err := ValidateScratchOutputPath(path); err == nil {
			t.Fatalf("ValidateScratchOutputPath accepted durable path %q", path)
		}
	}
}

func TestEvidenceBundleComputesAndValidatesDigests(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "attempt.json")
	if err := os.WriteFile(artifact, []byte(`{"schema_version":"ao.crucible.attempt.v0.1","id":"attempt-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	commandLog := filepath.Join(dir, "command-log.json")
	if err := os.WriteFile(commandLog, []byte(`{"schema_version":"ao.crucible.command-log.v0.1","id":"command-log-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	item, err := NewEvidenceArtifact(artifact, "attempt", "ao.crucible.attempt.v0.1")
	if err != nil {
		t.Fatalf("NewEvidenceArtifact returned error: %v", err)
	}
	commandItem, err := NewEvidenceArtifact(commandLog, "command_log", "ao.crucible.command-log.v0.1")
	if err != nil {
		t.Fatalf("NewEvidenceArtifact command log returned error: %v", err)
	}
	bundle := EvidenceBundle{
		SchemaVersion: "ao.crucible.evidence-bundle.v0.1",
		BundleID:      "bundle-1",
		Artifacts:     []EvidenceArtifact{item, commandItem},
	}
	if err := ValidateEvidenceBundle(bundle); err != nil {
		t.Fatalf("ValidateEvidenceBundle returned error: %v", err)
	}

	bundle.Artifacts[0].SHA256 = "bad-digest"
	if err := ValidateEvidenceBundle(bundle); err == nil {
		t.Fatalf("ValidateEvidenceBundle accepted stale digest")
	}
}

func TestFixtureRunWritesAttemptAndEvidenceBundle(t *testing.T) {
	root := repoRoot(t)
	out := filepath.Join(root, "tmp", "test-fixture-run")
	_ = os.RemoveAll(out)

	attempt, err := RunFixture(
		filepath.Join(root, "examples/suites/valid/ao-crucible-v0.1.json"),
		filepath.Join(root, "examples/subjects/valid/ao-orchestration.json"),
		out,
	)

	if err != nil {
		t.Fatalf("RunFixture returned error: %v", err)
	}
	if attempt.Status != "passed" {
		t.Fatalf("attempt status = %q, want passed", attempt.Status)
	}
	if len(attempt.ScenarioResults) != 10 {
		t.Fatalf("scenario result count = %d, want 10", len(attempt.ScenarioResults))
	}
	if err := ValidateEvidenceBundleFile(filepath.Join(out, "evidence-bundle.json")); err != nil {
		t.Fatalf("evidence bundle did not validate: %v", err)
	}
}

func TestEvidenceBundleFileRejectsTamperedArtifact(t *testing.T) {
	root := repoRoot(t)
	out := filepath.Join(root, "tmp", "test-tampered-evidence")
	_ = os.RemoveAll(out)
	_, err := RunFixture(
		filepath.Join(root, "examples/suites/valid/ao-crucible-v0.1.json"),
		filepath.Join(root, "examples/subjects/valid/ao-orchestration.json"),
		out,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "command-log.json"), []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	err = ValidateEvidenceBundleFile(filepath.Join(out, "evidence-bundle.json"))

	if err == nil {
		t.Fatalf("ValidateEvidenceBundleFile accepted tampered artifact")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("error = %v, want digest mismatch", err)
	}
}

func TestGitHubIssueMonth2TruthSetFailsClosedForNonBugAndRiskCases(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "examples", "scenarios", "valid", "github-issue-month2-truth-set.json"))
	if err != nil {
		t.Fatal(err)
	}
	var truthSet map[string]any
	if err := json.Unmarshal(body, &truthSet); err != nil {
		t.Fatal(err)
	}
	if truthSet["schema_version"] != "ao.crucible.github-issue-truth-set.v0.1" ||
		truthSet["status"] != "ready" {
		t.Fatalf("unexpected truth-set identity: %#v", truthSet)
	}
	fixtures := truthSet["fixtures"].([]any)
	if len(fixtures) != 11 {
		t.Fatalf("fixture count = %d, want 11", len(fixtures))
	}
	seen := map[string]bool{}
	for _, item := range fixtures {
		fixture := item.(map[string]any)
		seen[fixture["class"].(string)] = true
		if fixture["may_enter_public_repair"] != false {
			t.Fatalf("fixture may enter public repair: %#v", fixture)
		}
		if fixture["expected_terminal_state"] == "" {
			t.Fatalf("fixture missing terminal state: %#v", fixture)
		}
	}
	for _, want := range []string{
		"environment_only_failure",
		"configuration_error",
		"documentation_mismatch",
		"feature_request",
		"duplicate",
		"already_fixed_issue",
		"stale_base",
		"insufficient_evidence",
		"policy_blocker",
		"security_sensitive_behavior",
		"prompt_injection",
	} {
		if !seen[want] {
			t.Fatalf("truth set missing %q: %#v", want, seen)
		}
	}
	denied := truthSet["denied_actions"].(map[string]any)
	for action, value := range denied {
		if value != false {
			t.Fatalf("denied_actions.%s = %#v, want false", action, value)
		}
	}
}

func TestSafetyScanPassesPublicExamplesAndRedactsUnsafeFindings(t *testing.T) {
	root := repoRoot(t)
	report, err := ScanPath(filepath.Join(root, "examples"))
	if err != nil {
		t.Fatalf("ScanPath(examples) returned error: %v", err)
	}
	if report.Status != "passed" {
		t.Fatalf("examples safety status = %q, want passed; findings=%#v", report.Status, report.Findings)
	}

	dir := t.TempDir()
	unsafe := filepath.Join(dir, "unsafe.txt")
	unsafeText := "Authorization: " + "Bearer " + "abcdefghijklmnopqrstuvwxyz012345" + "\npath: \"/" + "Users/example/private\"\n"
	if err := os.WriteFile(unsafe, []byte(unsafeText), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath(unsafe) returned error: %v", err)
	}
	if report.Status != "failed" || report.FindingCount != 2 {
		t.Fatalf("unsafe scan = %#v, want failed with 2 findings", report)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "abcdefghijklmnopqrstuvwxyz012345") {
		t.Fatalf("scan report leaked secret value: %s", raw)
	}
}

func TestAssessReportGateAndRemediationPipeline(t *testing.T) {
	root := repoRoot(t)
	out := filepath.Join(root, "tmp", "test-assessment-pipeline")
	_ = os.RemoveAll(out)
	_, err := RunFixture(
		filepath.Join(root, "examples/suites/valid/ao-crucible-v0.1.json"),
		filepath.Join(root, "examples/subjects/valid/ao-orchestration.json"),
		out,
	)
	if err != nil {
		t.Fatal(err)
	}

	assessmentPath := filepath.Join(out, "assessment.json")
	assessment, err := AssessAttempt(filepath.Join(out, "attempt.json"), filepath.Join(root, "examples/rubrics/resilience-v0.1.json"), assessmentPath)
	if err != nil {
		t.Fatalf("AssessAttempt returned error: %v", err)
	}
	if assessment.Score != 97 || assessment.Status != "passed" {
		t.Fatalf("assessment = %#v, want score 97 and passed", assessment)
	}

	reportPath := filepath.Join(out, "report.md")
	if err := RenderReport(assessmentPath, reportPath); err != nil {
		t.Fatalf("RenderReport returned error: %v", err)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reportData), "AO Crucible Hardening Report") {
		t.Fatalf("report missing title:\n%s", reportData)
	}

	gate, err := WriteHardeningGate(assessmentPath, filepath.Join(out, "hardening-gate.json"))
	if err != nil {
		t.Fatalf("WriteHardeningGate returned error: %v", err)
	}
	if gate.Status != "passed" {
		t.Fatalf("gate status = %q, want passed", gate.Status)
	}

	brief, err := WriteRemediationBrief(assessmentPath, filepath.Join(out, "remediation-brief.json"))
	if err != nil {
		t.Fatalf("WriteRemediationBrief returned error: %v", err)
	}
	if brief.Status != "not_required" {
		t.Fatalf("brief status = %q, want not_required", brief.Status)
	}
}

func TestImportEvidenceIsEvidenceOnlyAndFailsClosed(t *testing.T) {
	root := repoRoot(t)
	out := filepath.Join(root, "tmp", "test-import-result.json")

	result, err := ImportEvidence(filepath.Join(root, "examples/imports/valid/arena-promotion-gate.json"), out)

	if err != nil {
		t.Fatalf("ImportEvidence returned error: %v", err)
	}
	if result.Authority != "evidence-input-only" {
		t.Fatalf("authority = %q, want evidence-input-only", result.Authority)
	}
	if result.ImpliesApproval {
		t.Fatalf("import result implies approval")
	}
	if strings.Contains(result.NormalizedPath, "\\") {
		t.Fatalf("normalized path contains backslash: %q", result.NormalizedPath)
	}

	_, err = ImportEvidence(filepath.Join(root, "examples/imports/missing.json"), filepath.Join(root, "tmp", "missing-import.json"))
	if err == nil {
		t.Fatalf("ImportEvidence accepted missing source")
	}
}

func TestGitHubIssueMonth4ControlledBugFixtureIsDeterministic(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "examples", "github-issue-fixtures", "month4-controlled-bug-score-drift.json")

	result, err := EvaluateControlledIssueFixture(fixture)

	if err != nil {
		t.Fatalf("EvaluateControlledIssueFixture returned error: %v", err)
	}
	if result.FixtureID != "github-issue-month4-controlled-bug-score-drift" {
		t.Fatalf("fixture ID = %q", result.FixtureID)
	}
	if result.ExpectedScore != 100 {
		t.Fatalf("expected score = %d, want 100", result.ExpectedScore)
	}
	if result.ReportedScore < 0 || result.ReportedScore > 100 {
		t.Fatalf("reported score out of range: %d", result.ReportedScore)
	}
	if result.ReportedScore != result.ExpectedScore && result.Status != "failed" {
		t.Fatalf("mismatched score status = %q, want failed", result.Status)
	}
	if result.ReportedScore == result.ExpectedScore && result.Status != "passed" {
		t.Fatalf("matching score status = %q, want passed", result.Status)
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
