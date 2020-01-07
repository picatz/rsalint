package main

import (
	"github.com/picatz/rsalint/rsacheck"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(rsacheck.Analyzer)
}
