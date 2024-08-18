package rsacheck

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestVulnerable(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer, "vulnerable")
}

func TestNotVulnerable(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer, "not-vulnerable")
}
