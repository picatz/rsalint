package rsacheck

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	if Analyzer.Name != "rsalint" {
		t.Fatalf("Unexpected analyzer name found, exp: %q, got: %q", "rsalint", Analyzer.Name)
	}

	if Analyzer.Doc == "" {
		t.Error("No analyzer doc string found.")
	}
}

func TestVulnerable(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer, "vulnerable")
}
