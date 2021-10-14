package rsacheck

import "testing"

func TestAnalyzer(t *testing.T) {
	if Analyzer.Name != "rsalint" {
		t.Fatalf("Unexpected analyzer name found, exp: %q, got: %q", "rsalint", Analyzer.Name)
	}

	if Analyzer.Doc == "" {
		t.Error("No analyzer doc string found.")
	}
}
