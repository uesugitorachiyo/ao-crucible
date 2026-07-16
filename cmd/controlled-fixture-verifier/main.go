package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ao-foundry/ao-crucible/internal/crucible"
)

func main() {
	fixture := flag.String("fixture", "", "controlled issue fixture path")
	flag.Parse()
	if *fixture == "" {
		fmt.Fprintln(os.Stderr, "missing --fixture")
		os.Exit(2)
	}

	result, err := crucible.EvaluateControlledIssueFixture(*fixture)
	if err != nil {
		fmt.Fprintf(os.Stderr, "controlled fixture invalid: %v\n", err)
		os.Exit(2)
	}
	body, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "controlled fixture result encode failed: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(body))
	if result.Status != "passed" {
		os.Exit(1)
	}
}
