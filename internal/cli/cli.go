package cli

import (
	"fmt"
	"io"

	"github.com/ao-foundry/ao-crucible/internal/crucible"
)

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printHelp(stdout)
		return 0
	}

	var err error
	switch args[0] {
	case "suite":
		err = runSuite(args[1:], stdout)
	case "scenario":
		err = runScenario(args[1:], stdout)
	case "subject":
		err = runSubject(args[1:], stdout)
	case "rubric":
		err = runRubric(args[1:], stdout)
	case "probe":
		err = runProbe(args[1:], stdout)
	case "run":
		err = runRunner(args[1:], stdout)
	case "evidence":
		err = runEvidence(args[1:], stdout)
	case "assess":
		err = runAssess(args[1:], stdout)
	case "report":
		err = runReport(args[1:], stdout)
	case "gate":
		err = runGate(args[1:], stdout)
	case "safety":
		err = runSafety(args[1:], stdout)
	case "remediation":
		err = runRemediation(args[1:], stdout)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}

	if err != nil {
		fmt.Fprintf(stderr, "crucible: %v\n", err)
		return 1
	}
	return 0
}

func printHelp(out io.Writer) {
	fmt.Fprintln(out, `AO Crucible fixture-mode adversarial hardening CLI

Commands:
  suite validate --suite <path>
  scenario validate --scenario <path>
  subject validate --subject <path>
  rubric validate --rubric <path>
  probe catalog --out <path>
  run fixture --suite <path> --subject <path> --out <dir>
  evidence validate --bundle <path>
  assess --attempt <path> --rubric <path> --out <path>
  report render --assessment <json> --out <markdown>
  gate hardening --assessment <json> --out <json>
  safety scan --path <path> --out <json>
  remediation brief --assessment <json> --out <json>`)
}

func runSuite(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return fmt.Errorf("usage: crucible suite validate --suite <path>")
	}
	path := flagValue(args[1:], "--suite")
	if path == "" {
		return fmt.Errorf("missing --suite")
	}
	if _, err := crucible.LoadAndValidateSuite(path); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "suite valid")
	return nil
}

func runScenario(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return fmt.Errorf("usage: crucible scenario validate --scenario <path>")
	}
	path := flagValue(args[1:], "--scenario")
	if path == "" {
		return fmt.Errorf("missing --scenario")
	}
	if err := crucible.ValidateScenario(path); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "scenario valid")
	return nil
}

func runSubject(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return fmt.Errorf("usage: crucible subject validate --subject <path>")
	}
	path := flagValue(args[1:], "--subject")
	if path == "" {
		return fmt.Errorf("missing --subject")
	}
	if _, err := crucible.LoadAndValidateSubject(path); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "subject valid")
	return nil
}

func runRubric(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return fmt.Errorf("usage: crucible rubric validate --rubric <path>")
	}
	path := flagValue(args[1:], "--rubric")
	if path == "" {
		return fmt.Errorf("missing --rubric")
	}
	if _, err := crucible.LoadAndValidateRubric(path); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "rubric valid")
	return nil
}

func runProbe(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "catalog" {
		return fmt.Errorf("usage: crucible probe catalog --out <path>")
	}
	out := flagValue(args[1:], "--out")
	if out == "" {
		return fmt.Errorf("missing --out")
	}
	catalog, err := crucible.WriteProbeCatalog(out)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "probe catalog written: %d probes\n", len(catalog.Probes))
	return nil
}

func runRunner(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "fixture" {
		return fmt.Errorf("usage: crucible run fixture --suite <path> --subject <path> --out <dir>")
	}
	suite := flagValue(args[1:], "--suite")
	subject := flagValue(args[1:], "--subject")
	out := flagValue(args[1:], "--out")
	if suite == "" || subject == "" || out == "" {
		return fmt.Errorf("missing --suite, --subject, or --out")
	}
	attempt, err := crucible.RunFixture(suite, subject, out)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "fixture run written: %d scenarios status=%s\n", len(attempt.ScenarioResults), attempt.Status)
	return nil
}

func runEvidence(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return fmt.Errorf("usage: crucible evidence validate --bundle <path>")
	}
	bundle := flagValue(args[1:], "--bundle")
	if bundle == "" {
		return fmt.Errorf("missing --bundle")
	}
	if err := crucible.ValidateEvidenceBundleFile(bundle); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "evidence bundle valid")
	return nil
}

func runAssess(args []string, stdout io.Writer) error {
	attempt := flagValue(args, "--attempt")
	rubric := flagValue(args, "--rubric")
	out := flagValue(args, "--out")
	if attempt == "" || rubric == "" || out == "" {
		return fmt.Errorf("usage: crucible assess --attempt <path> --rubric <path> --out <path>")
	}
	assessment, err := crucible.AssessAttempt(attempt, rubric, out)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "assessment written: score=%d status=%s\n", assessment.Score, assessment.Status)
	return nil
}

func runReport(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "render" {
		return fmt.Errorf("usage: crucible report render --assessment <json> --out <markdown>")
	}
	assessment := flagValue(args[1:], "--assessment")
	out := flagValue(args[1:], "--out")
	if assessment == "" || out == "" {
		return fmt.Errorf("missing --assessment or --out")
	}
	if err := crucible.RenderReport(assessment, out); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "hardening report written")
	return nil
}

func runGate(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "hardening" {
		return fmt.Errorf("usage: crucible gate hardening --assessment <json> --out <json>")
	}
	assessment := flagValue(args[1:], "--assessment")
	out := flagValue(args[1:], "--out")
	if assessment == "" || out == "" {
		return fmt.Errorf("missing --assessment or --out")
	}
	gate, err := crucible.WriteHardeningGate(assessment, out)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "hardening gate written: status=%s\n", gate.Status)
	return nil
}

func runSafety(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: crucible safety scan --path <path> --out <json>")
	}
	path := flagValue(args[1:], "--path")
	out := flagValue(args[1:], "--out")
	if path == "" || out == "" {
		return fmt.Errorf("missing --path or --out")
	}
	report, err := crucible.WriteSafetyScan(path, out)
	if err != nil {
		return err
	}
	if report.Status != "passed" {
		return fmt.Errorf("safety scan failed with %d findings", report.FindingCount)
	}
	fmt.Fprintf(stdout, "safety scan written: status=%s\n", report.Status)
	return nil
}

func runRemediation(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "brief" {
		return fmt.Errorf("usage: crucible remediation brief --assessment <json> --out <json>")
	}
	assessment := flagValue(args[1:], "--assessment")
	out := flagValue(args[1:], "--out")
	if assessment == "" || out == "" {
		return fmt.Errorf("missing --assessment or --out")
	}
	brief, err := crucible.WriteRemediationBrief(assessment, out)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "remediation brief written: status=%s\n", brief.Status)
	return nil
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}
