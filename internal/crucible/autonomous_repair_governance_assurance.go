package crucible

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const AutonomousRepairGovernanceAssuranceSchemaVersion = "ao.crucible.autonomous-repair-governance-assurance.v1"

type AutonomousRepairGovernanceAssurance struct {
	SchemaVersion   string                                    `json:"schema_version"`
	SuiteID         string                                    `json:"suite_id"`
	Provenance      AutonomousRepairGovernanceProvenance      `json:"provenance"`
	SafetyBoundary  AutonomousRepairGovernanceSafetyBoundary  `json:"safety_boundary"`
	Cases           []AutonomousRepairGovernanceAssuranceCase `json:"cases"`
	CanonicalDigest string                                    `json:"canonical_digest"`
}

type AutonomousRepairGovernanceProvenance struct {
	Architecture AutonomousRepairGovernanceArchitectureSource `json:"architecture"`
	Covenant     AutonomousRepairGovernanceCovenantSources    `json:"covenant"`
	AO2          AutonomousRepairGovernanceSource             `json:"ao2"`
}

type AutonomousRepairGovernanceCovenantSources struct {
	Commit                 string                         `json:"commit"`
	ExecutionPolicy        AutonomousRepairGovernanceFile `json:"execution_policy"`
	GovernancePolicySchema AutonomousRepairGovernanceFile `json:"governance_policy_schema"`
	GovernanceRuntime      AutonomousRepairGovernanceFile `json:"governance_runtime"`
	ArchitectureRuntime    AutonomousRepairGovernanceFile `json:"architecture_runtime"`
}

type AutonomousRepairGovernanceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type AutonomousRepairGovernanceArchitectureSource struct {
	Repository      string `json:"repository"`
	Commit          string `json:"commit"`
	Path            string `json:"path"`
	SourceSHA256    string `json:"source_sha256"`
	SemanticsSHA256 string `json:"semantics_sha256"`
}

type AutonomousRepairGovernanceSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
}

type AutonomousRepairGovernanceSafetyBoundary struct {
	Mode                string `json:"mode"`
	LiveProviderUsed    bool   `json:"live_provider_used"`
	NetworkUsed         bool   `json:"network_used"`
	CredentialsUsed     bool   `json:"credentials_used"`
	GitHubMutation      bool   `json:"github_mutation"`
	SiblingRepoMutation bool   `json:"sibling_repo_mutation"`
}

type AutonomousRepairGovernanceAssuranceCase struct {
	CaseID      string                                    `json:"case_id"`
	Input       AutonomousRepairGovernanceAssuranceInput  `json:"input"`
	InputSHA256 string                                    `json:"input_sha256"`
	Expected    AutonomousRepairGovernanceAssuranceResult `json:"expected"`
}

type AutonomousRepairGovernanceAssuranceInput struct {
	RepositoryClass       string `json:"repository_class"`
	SoleAutoMergeOptIn    bool   `json:"sole_auto_merge_opt_in"`
	Action                string `json:"action"`
	ProtectedPathTouched  bool   `json:"protected_path_touched"`
	RequiredChecksGreen   bool   `json:"required_checks_green"`
	ReviewerRelationship  string `json:"reviewer_relationship"`
	ReviewerID            string `json:"reviewer_id"`
	ApprovalKind          string `json:"approval_kind"`
	ApprovalHeadMatches   bool   `json:"approval_head_matches"`
	ActionDigestMatches   bool   `json:"action_digest_matches"`
	ApprovalUnexpired     bool   `json:"approval_unexpired"`
	ForkState             string `json:"fork_state"`
	BranchState           string `json:"branch_state"`
	DraftPRState          string `json:"draft_pr_state"`
	ExpiryCheckpoint      string `json:"expiry_checkpoint"`
	ForceUpdateRequested  bool   `json:"force_update_requested"`
	UpstreamPushRequested bool   `json:"upstream_push_requested"`
}

type AutonomousRepairGovernanceAssuranceResult struct {
	Authorized    bool   `json:"authorized"`
	ReasonCode    string `json:"reason_code"`
	WriteCount    int    `json:"write_count"`
	TerminalState string `json:"terminal_state"`
}

var autonomousRepairGovernanceAssuranceCaseIDs = []string{
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

var autonomousRepairGovernanceAssuranceInputSHA256 = []string{
	"fd07d31048cc3f5dcd26255bdb55bd4bdc9771f762790d0894e2d925e97222ea",
	"4d50c354dd289b9b211d91ba53936b0326c2b33f12898c6cb8184b8682d9f816",
	"09a052980429ac1d1fa63ae2de6004ddb27ecbb92e9569cbc6e25d2c9237e64b",
	"41ccfdfef6641cffd23483a376a17342df67fddbc2fe95d33fb07d570a37aac8",
	"83b74af2d52f225ee2dcc5bc6476209562a18e6c4f55e6e1b65759ca16586a48",
	"f8d391f8cb6df5c7fd8fe93eff5658e4b13a3b9bcd46353c0d1e3c963b8fb706",
	"b71ae02a198d9eab195897531118d23dad94e5a62fa369fd46bc05a7034cfe8a",
	"b5fc70a53d748202c7c8b2ba04cbb17780452a00f1e1cb4dcfd8851a560292ee",
	"bd76cfb5e3a0cf7f8efbde444b4147fbc179f0352fbc8e8b2fc0a2cb7b1b21b2",
	"5428249ac0b2d9f63ca27c900c56d26db2109cbc26f053aa4dbb60afbb43f07d",
	"5f8a0ef8227c72159a7a72722b2c29906cf32b53bc3d78dc25bf8fbb99078dad",
	"b5abce8552eed849b87395f2d07c557044de681ea42ddac9a9a04cb98f484f7f",
	"3f287b751fb5e5b9e5b281c389f266992b176bc4bfa10e4e90c189c484e1817d",
	"96f7fb92cad029eac9aab07f96121c191294df7933bd8ef466161d160bb1bb7f",
	"69ea84e3267be0aff5b86cc87b65b86804f44e11af3e043fbd6b22a7d70e790e",
	"e30ec189936f0935de08e8dd8fd8a7a546c660cdf7fd42f1204eaf72e25ebd74",
	"0d5a2c2bceaefc1ff0997608a9532ab65d9218e1e1391b5245b4cda00c5467a7",
	"d0536e2a115ac4ee2e82383b9b01d95c06c90d078d70fc0cfbc0baa4d837c142",
	"f624003ce69d273edf8b2c30ff46c3e3401432f08e31f515212701633c1b87a6",
	"dd46662320c002323d27023f4f0a1c3b77c4310945817404937dff0db6f15032",
	"74d153005d9a40ed248ff92abf0189c415a69bec00deed54d6ce177fc4698d11",
	"072e1d129b46ac67ee623b3e01fcd133a83433a021adaf73b5957ec426e0896b",
	"93dc4d45fc393d36610222d993fb9e189264ca9140e3192f0fb14f8dc85d3d2b",
	"1823676df19d4919d4c6e8d668ed8fc1d61e994bbd3dc93a3acd6c79409cfb9b",
	"91ba6c70d097281cd4a908653327a8f789f50d6485878bdd6176a1d68568b819",
	"f19c5a56e4b968d720588c4d301fb82e563cd7555f979f3d4c54447a2f0b8bb1",
	"c74cfddffdafeb92f0cda0c694cb85b6a9bd28f1801a7bf5b088e7b5ffcdffb7",
	"2e925b5e38a796ff6c64faa648a95b0d67f38049465ab50900f9257667f9cca5",
	"9b0553b3775eaa360b5dc0cf35a381b0b4a2cc0ea2b4673ea7657c967259ecfe",
	"7e6f045cbc7bd929411775054e58245023b041efbff28a1389fe587988604d2c",
	"56a97b46b8c8d31fae74a8566c20e44863e324c179430411ba829ea83fa148e4",
	"1324f131ca90e9141e3bc2bde414faf76a5790bcc0051e4f390e63e8845a20f8",
	"e2dfcb9837aad1c066073444a00dc4e2ee485f3231a4f71d8c9a8454aa302a42",
	"bec3b8155dad2a3482d6b2a8a0c348c21ebf21cd6a7231c02d2405677e5c153b",
	"ed00b750ffef53510fec6e8b35156d234d4b0c7b5f9c3375ede43910009efba4",
	"07d10539acc7c789068b26c477254cca0700e2ccd9111b9cd4b21f8547b596d7",
	"5b82b4761ac8aae977a15f4bfd5f62aea1425c2e7db956b94d58f1dfa7b5773b",
	"903cd0fd0a967ef597be5d98945611ea1c8dab3acbfb75c65fce684d54d144a4",
	"f7dc590376714b7bd5e6ae22fd756a78410787948bbd26488603a5e2f61cdea7",
	"399b8f98d28e0e4fb6b901b9578859134c7cbc546f08a435a251acafaa756d63",
	"7954c6665edcedb397d1a99c3836ec9e609785ac6577a51f6ea1abd1c594a265",
	"c0bd641858ca1adf2189b516ba5ef8b97e25a759e52f8b742a79a628775194c1",
	"5745ad97aa32979956fc30e1d6080784ce7337b4345ed76b2625c305014ad0a4",
	"33ae24541d644440d3f783867841334ab2af8eb74f6a412a2738157a9a2fba2f",
	"4fbd67bda52966489a49d9eeb7c5898065034da5f02bcbf11efcf283cb1a75d2",
	"2394f4751e7363a7c8f6f3bf9319a7c65afa1e486f210b72d353564a9fd4b141",
	"86b65b1579c119076dde101d67541988689503d1e0432ac7b6c6dd06df3ed9a3",
}

func LoadAndValidateAutonomousRepairGovernanceAssurance(path string) (AutonomousRepairGovernanceAssurance, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return AutonomousRepairGovernanceAssurance{}, err
	}
	return DecodeAndValidateAutonomousRepairGovernanceAssurance(data)
}

func DecodeAndValidateAutonomousRepairGovernanceAssurance(data []byte) (AutonomousRepairGovernanceAssurance, error) {
	var suite AutonomousRepairGovernanceAssurance
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return suite, fmt.Errorf("decode autonomous repair governance assurance: %w", err)
	}
	if err := validateAutonomousRepairGovernanceRequiredFields(data); err != nil {
		return suite, fmt.Errorf("decode autonomous repair governance assurance: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&suite); err != nil {
		return suite, fmt.Errorf("decode autonomous repair governance assurance: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return suite, fmt.Errorf("decode autonomous repair governance assurance: %w", err)
	}
	if err := validateAutonomousRepairGovernanceAssurance(suite); err != nil {
		return suite, err
	}
	return suite, nil
}

func CanonicalAutonomousRepairGovernanceAssuranceDigest(suite AutonomousRepairGovernanceAssurance) (string, error) {
	data, err := json.Marshal(suite)
	if err != nil {
		return "", err
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return "", err
	}
	delete(document, "canonical_digest")
	canonical, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func CanonicalAutonomousRepairGovernanceInputDigest(input AutonomousRepairGovernanceAssuranceInput) (string, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func EvaluateAutonomousRepairGovernanceAssurance(input AutonomousRepairGovernanceAssuranceInput) AutonomousRepairGovernanceAssuranceResult {
	denyAfterWrite := func(reason string, writeCount int) AutonomousRepairGovernanceAssuranceResult {
		return AutonomousRepairGovernanceAssuranceResult{
			ReasonCode:    reason,
			WriteCount:    writeCount,
			TerminalState: "denied",
		}
	}
	deny := func(reason string) AutonomousRepairGovernanceAssuranceResult {
		return denyAfterWrite(reason, 0)
	}
	allow := func(reason string, writeCount int) AutonomousRepairGovernanceAssuranceResult {
		return AutonomousRepairGovernanceAssuranceResult{
			Authorized:    true,
			ReasonCode:    reason,
			WriteCount:    writeCount,
			TerminalState: "authorized",
		}
	}
	switch input.Action {
	case "mutate_issue":
		return deny("issue_mutation_denied")
	case "approve_review":
		return deny("review_denied")
	case "merge":
		return deny("merge_denied")
	}
	if input.ProtectedPathTouched {
		return deny("protected_path")
	}
	if !input.RequiredChecksGreen {
		return deny("required_check_not_green")
	}
	if !input.ActionDigestMatches {
		return deny("action_digest_mismatch")
	}
	if !input.ApprovalUnexpired {
		return deny("approval_expired")
	}
	if input.ForceUpdateRequested {
		return deny("force_update_denied")
	}
	if input.UpstreamPushRequested {
		return deny("upstream_push_denied")
	}
	if input.Action == "push_operator_fork" {
		if input.ForkState == "mismatch" {
			return deny("fork_identity_mismatch")
		}
		if input.ForkState == "post_create_readback_mismatch" {
			return denyAfterWrite("fork_post_create_readback_mismatch", 1)
		}
		if input.BranchState == "mismatch" {
			return deny("branch_head_mismatch")
		}
		if input.BranchState == "post_create_readback_mismatch" {
			return denyAfterWrite("branch_post_push_readback_mismatch", 1)
		}
	}

	switch input.RepositoryClass {
	case "external", "unknown":
		switch input.Action {
		case "push_operator_fork":
			writes := 0
			if input.ForkState == "absent" {
				if input.ExpiryCheckpoint == "before_fork" {
					return deny("approval_expired_before_fork_write")
				}
				writes++
			}
			if input.BranchState == "absent" {
				if input.ExpiryCheckpoint == "before_branch" {
					return denyAfterWrite("approval_expired_before_branch_write", writes)
				}
				writes++
			}
			return allow("external_draft_only", writes)
		case "open_upstream_draft_pr":
			switch input.ForkState {
			case "absent":
				return deny("draft_fork_prerequisite_missing")
			case "mismatch":
				return deny("fork_identity_mismatch")
			case "post_create_readback_mismatch":
				return deny("fork_post_create_readback_mismatch")
			}
			switch input.BranchState {
			case "absent":
				return deny("draft_branch_prerequisite_missing")
			case "mismatch":
				return deny("branch_head_mismatch")
			case "post_create_readback_mismatch":
				return deny("branch_post_push_readback_mismatch")
			}
			switch input.DraftPRState {
			case "exact":
				return allow("external_draft_only", 0)
			case "mismatch":
				return deny("draft_pr_identity_mismatch")
			case "ambiguous":
				return deny("draft_lookup_ambiguous")
			case "absent":
				if input.ExpiryCheckpoint == "before_draft" {
					return deny("approval_expired_before_draft_write")
				}
				return allow("external_draft_only", 1)
			case "conflict_exact":
				return allow("external_draft_only", 1)
			case "conflict_missing":
				return denyAfterWrite("draft_conflict_reread_missing", 1)
			case "conflict_mismatch":
				return denyAfterWrite("draft_conflict_reread_identity_drift", 1)
			case "conflict_ambiguous":
				return denyAfterWrite("draft_conflict_reread_ambiguous", 1)
			case "post_create_readback_mismatch":
				return denyAfterWrite("draft_post_create_readback_mismatch", 1)
			}
			return deny("invalid_draft_state")
		default:
			return deny("external_draft_only")
		}
	case "team":
		if input.Action == "open_ready_pr" {
			return allow("team_bounded_action", 1)
		}
		if input.Action != "request_merge_queue" {
			return deny("team_auto_merge_denied")
		}
		if input.ReviewerRelationship != "independent" ||
			!containsString([]string{"independent_human", "codeowner"}, input.ApprovalKind) ||
			automatedGovernanceReviewer(input.ReviewerID) {
			return deny("independent_human_approval_required")
		}
		if !input.ApprovalHeadMatches {
			return deny("approval_head_mismatch")
		}
		return allow("team_merge_queue", 1)
	case "sole_control":
		if input.Action == "open_ready_pr" {
			return allow("sole_control_bounded_action", 1)
		}
		if input.Action != "auto_merge" {
			return deny("action_not_allowed")
		}
		if !input.SoleAutoMergeOptIn {
			return deny("sole_control_auto_merge_not_opted_in")
		}
		return allow("sole_control_auto_merge", 1)
	default:
		return deny("invalid_repository_class")
	}
}

func validateAutonomousRepairGovernanceAssurance(suite AutonomousRepairGovernanceAssurance) error {
	if suite.SchemaVersion != AutonomousRepairGovernanceAssuranceSchemaVersion ||
		suite.SuiteID != "stage5-autonomous-repair-github-governance-assurance" {
		return fmt.Errorf("invalid autonomous repair governance assurance identity")
	}
	if !validAutonomousRepairGovernanceProvenance(suite.Provenance) {
		return fmt.Errorf("autonomous repair governance assurance provenance mismatch")
	}
	if suite.SafetyBoundary != (AutonomousRepairGovernanceSafetyBoundary{Mode: "fixture_only"}) {
		return fmt.Errorf("autonomous repair governance assurance exceeds fixture-only boundary")
	}
	if len(suite.Cases) != len(autonomousRepairGovernanceAssuranceCaseIDs) {
		return fmt.Errorf("autonomous repair governance assurance must contain exactly %d cases", len(autonomousRepairGovernanceAssuranceCaseIDs))
	}
	seen := make(map[string]bool, len(suite.Cases))
	for index, testCase := range suite.Cases {
		if testCase.CaseID != autonomousRepairGovernanceAssuranceCaseIDs[index] || seen[testCase.CaseID] {
			return fmt.Errorf("autonomous repair governance assurance case identity mismatch")
		}
		seen[testCase.CaseID] = true
		if !validAutonomousRepairGovernanceInput(testCase.Input) {
			return fmt.Errorf("case %q has invalid governance input", testCase.CaseID)
		}
		inputDigest, err := CanonicalAutonomousRepairGovernanceInputDigest(testCase.Input)
		if err != nil ||
			testCase.InputSHA256 != inputDigest ||
			testCase.InputSHA256 != autonomousRepairGovernanceAssuranceInputSHA256[index] {
			return fmt.Errorf("case %q input digest mismatch", testCase.CaseID)
		}
		if derived := EvaluateAutonomousRepairGovernanceAssurance(testCase.Input); derived != testCase.Expected {
			return fmt.Errorf("case %q expected result contradicts pure governance derivation", testCase.CaseID)
		}
	}
	digest, err := CanonicalAutonomousRepairGovernanceAssuranceDigest(suite)
	if err != nil {
		return fmt.Errorf("compute autonomous repair governance assurance digest: %w", err)
	}
	if suite.CanonicalDigest != digest {
		return fmt.Errorf("autonomous repair governance assurance canonical digest mismatch")
	}
	return nil
}

func validAutonomousRepairGovernanceProvenance(provenance AutonomousRepairGovernanceProvenance) bool {
	return provenance.Architecture == (AutonomousRepairGovernanceArchitectureSource{
		Repository:      "uesugitorachiyo/ao-architecture",
		Commit:          "8e6f247b800b60c520b4e967f7553974a20ec2f8",
		Path:            "stack/github-issue-workflow-contracts.json",
		SourceSHA256:    "60bd07fa4e02d38f0321aa138bb53ca3f89e44499621a7e0369065bca88889ae",
		SemanticsSHA256: "2c6835289c508cd2954df545f93a1262c0616de87917bb1f749488376087b9b4",
	}) &&
		provenance.Covenant == (AutonomousRepairGovernanceCovenantSources{
			Commit: "561c167c57199913d4e2fa2692c21da68a2ecae6",
			ExecutionPolicy: AutonomousRepairGovernanceFile{
				Path:   "schemas/covenant.autonomous-repair-github-execution-policy.v1.schema.json",
				SHA256: "a024cb61fb147417317031a08f741d9d47970d58bc244f0d66765eee1bbd1ee0",
			},
			GovernancePolicySchema: AutonomousRepairGovernanceFile{
				Path:   "schemas/covenant.autonomous-repair-governance-policy.v1.schema.json",
				SHA256: "c2555224e70e03258ba2c29247a8892f20b3eab45b8ba2a7cfaea2fd5b400332",
			},
			GovernanceRuntime: AutonomousRepairGovernanceFile{
				Path:   "internal/policy/autonomous_repair_governance.go",
				SHA256: "2eb07271105e133c16587061dc2c2e7800a4b3e756025f9dda135e5807a73349",
			},
			ArchitectureRuntime: AutonomousRepairGovernanceFile{
				Path:   "internal/policy/autonomous_repair_architecture.go",
				SHA256: "d9fd74293e2bc286165b5f64b5dae2c4c64a8fdf43f54cc75abbb246ba81d03b",
			},
		}) &&
		provenance.AO2 == (AutonomousRepairGovernanceSource{
			Repository: "uesugitorachiyo/ao2",
			Commit:     "627c53f952bae5a638ce25ed934a81d01527a9f1",
			Path:       "crates/ao2-runtime/src/github_issue_publication.rs",
			SHA256:     "b6113a2de991b8b6a346d40ee0bd2cf5ceb677f64226ecad9fd9f9394dfd066c",
		})
}

func validAutonomousRepairGovernanceInput(input AutonomousRepairGovernanceAssuranceInput) bool {
	return containsString([]string{"sole_control", "team", "external", "unknown"}, input.RepositoryClass) &&
		containsString([]string{
			"push_operator_fork",
			"open_upstream_draft_pr",
			"request_merge_queue",
			"auto_merge",
			"mutate_issue",
			"open_ready_pr",
			"approve_review",
			"merge",
		}, input.Action) &&
		containsString([]string{"independent", "same_vendor", "unavailable", "unverified"}, input.ReviewerRelationship) &&
		input.ReviewerID != "" && len(input.ReviewerID) <= 128 &&
		containsString([]string{"none", "independent_human", "codeowner"}, input.ApprovalKind) &&
		containsString([]string{"absent", "exact", "mismatch", "post_create_readback_mismatch"}, input.ForkState) &&
		containsString([]string{"absent", "exact", "mismatch", "post_create_readback_mismatch"}, input.BranchState) &&
		containsString([]string{
			"absent", "exact", "mismatch", "ambiguous", "conflict_exact",
			"conflict_missing", "conflict_mismatch", "conflict_ambiguous",
			"post_create_readback_mismatch",
		}, input.DraftPRState) &&
		containsString([]string{"all_writes", "before_fork", "before_branch", "before_draft"}, input.ExpiryCheckpoint)
}

func automatedGovernanceReviewer(reviewerID string) bool {
	normalized := strings.ToLower(reviewerID)
	return strings.Contains(normalized, "automated") ||
		strings.Contains(normalized, "[bot]") ||
		strings.HasPrefix(normalized, "ao-") ||
		strings.HasPrefix(normalized, "codex")
}

func validateAutonomousRepairGovernanceRequiredFields(data []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	for _, field := range []string{
		"schema_version", "suite_id", "provenance", "safety_boundary", "cases", "canonical_digest",
	} {
		if _, ok := document[field]; !ok {
			return fmt.Errorf("missing required field %q", field)
		}
	}
	var safety map[string]json.RawMessage
	if err := json.Unmarshal(document["safety_boundary"], &safety); err != nil {
		return err
	}
	for _, field := range []string{
		"mode", "live_provider_used", "network_used", "credentials_used",
		"github_mutation", "sibling_repo_mutation",
	} {
		if _, ok := safety[field]; !ok {
			return fmt.Errorf("safety boundary missing required field %q", field)
		}
	}
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(document["cases"], &cases); err != nil {
		return err
	}
	for index, testCase := range cases {
		for _, field := range []string{"case_id", "input", "input_sha256", "expected"} {
			if _, ok := testCase[field]; !ok {
				return fmt.Errorf("case %d missing required field %q", index, field)
			}
		}
		var input map[string]json.RawMessage
		if err := json.Unmarshal(testCase["input"], &input); err != nil {
			return err
		}
		for _, field := range []string{
			"repository_class", "sole_auto_merge_opt_in", "action",
			"protected_path_touched", "required_checks_green", "reviewer_relationship", "reviewer_id", "approval_kind",
			"approval_head_matches", "action_digest_matches", "approval_unexpired",
			"fork_state", "branch_state", "draft_pr_state", "expiry_checkpoint", "force_update_requested",
			"upstream_push_requested",
		} {
			if _, ok := input[field]; !ok {
				return fmt.Errorf("case %d input missing required field %q", index, field)
			}
		}
		var expected map[string]json.RawMessage
		if err := json.Unmarshal(testCase["expected"], &expected); err != nil {
			return err
		}
		for _, field := range []string{"authorized", "reason_code", "write_count", "terminal_state"} {
			if _, ok := expected[field]; !ok {
				return fmt.Errorf("case %d expected result missing required field %q", index, field)
			}
		}
	}
	return nil
}
