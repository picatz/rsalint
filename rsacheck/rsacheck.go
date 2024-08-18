// Package rsacheck defines an Analyzer to report insecure usage of the "crypto/rsa" package.
package rsacheck

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// Functions that are analyzed by this analyzer.
const (
	randomReader          = "crypto/rand.Reader"
	generateKey           = "crypto/rsa.GenerateKey"
	generateMultiPrimeKey = "crypto/rsa.GenerateMultiPrimeKey"
	encryptPKCS1v15       = "crypto/rsa.EncryptPKCS1v15"
)

// Messages that are reported by this analyzer.
const (
	randSourceLintMessage     = "use the crypto/rand.Reader for a cryptographically secure random number generator"
	numberOfbitsLintMessage   = "use 2048 bits or greater"
	numberOfPrimesLintMessage = "for %v bits %v is the max number of primes to use"
	multipleOf8BitsMessage    = "use a multiple of 8 bits for RSA keys"
	generateKeyMessage        = "use rsa.GenerateKey instead of rsa.GenerateMultiPrimeKey"
	oaepMessage               = "use rsa.EncryptOAEP instead of rsa.EncryptPKCS1v15"
)

// maxPrimesTable is a table that maps the number of bits to the recommended number of primes to use.
// This is to avoid the use of RSA with a weak number of primes, which can be easily broken.
//
// http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
// num-bits -> rec-num-of-primes
var maxPrimesTable = map[int]int{
	1024: 3,
	2048: 3,
	4096: 4,
	8192: 5,
}

// Analyzer that reports insecure usage of the "crypto/rsa" package by checking for the following:
//   - Weak random source (not using crypto/rand.Reader).
//   - Weak number of bits (less than 2048, and not a multiple of 8).
//   - Weak number of primes for the given number of bits.
//   - Deprecated functions (rsa.GenerateMultiPrimeKey).
//   - Insecure encryption schemes (rsa.EncryptPKCS1v15).
var Analyzer = &analysis.Analyzer{
	Name: "rsalint",
	Doc:  "report insecure usage of the \"crypto/rsa\" package",
	Run:  run,
	Requires: []*analysis.Analyzer{
		buildssa.Analyzer,
	},
}

// checkSecureRandomReader checks if the random source is known secure (crypto/rand.Reader).
// This is to avoid the use of a weak random source, which can be easily predicted, and thus broken.
func checkSecureRandomReader(pass *analysis.Pass, instr *ssa.Call, value ssa.Value) {
	switch value := value.(type) {
	case *ssa.Call:
		if value.Call.Value.String() != randomReader {
			pass.Reportf(instr.Pos(), randSourceLintMessage)
		}
	case *ssa.MakeInterface:
		checkSecureRandomReader(pass, instr, value.X)
	}
}

// checkBits checks if the number of bits is within the recommended range for the given number of bits.
// This is to avoid the use of RSA with a weak number of bits, which can be easily broken.
//
// The recommended number of bits is 2048 or greater, as per NIST SP 800-57 Part 1 Rev. 4.
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
func checkBits(pass *analysis.Pass, instr *ssa.Call, bits ssa.Value) {
	bitsValue, ok := bits.(*ssa.Const)
	if !ok {
		return
	}

	if bitsValue.Int64() < 2048 {
		pass.Reportf(instr.Pos(), numberOfbitsLintMessage)
	}

	// Also ensure it's a proper multiple of 8
	if bitsValue.Int64()%8 != 0 {
		pass.Reportf(instr.Pos(), multipleOf8BitsMessage)
	}
}

// checkNPrimesForBits checks if the number of primes is within the recommended range for the
// given number of bits. This is to avoid the use of RSA with a weak number of primes.
func checkNPrimesForBits(pass *analysis.Pass, instr *ssa.Call, nprimes, bits ssa.Value) {
	nprimesValue, ok := nprimes.(*ssa.Const)
	if !ok {
		return
	}

	bitsValue, ok := bits.(*ssa.Const)
	if !ok {
		return
	}

	recMaxNum, ok := maxPrimesTable[int(bitsValue.Int64())]
	if ok && nprimesValue.Int64() > int64(recMaxNum) {
		pass.Reportf(instr.Pos(), numberOfPrimesLintMessage, bitsValue.Int64(), recMaxNum)
	}
}

// checkRSAGenerateKey checks if the [crypto/rsa.GenerateMultiPrimeKey] function is being used securely,
// even though it is not recommended to use this function, and has been deprecated.
func checkGenerateMultiPrimeKey(pass *analysis.Pass, instr *ssa.Call) {
	var (
		random  = instr.Call.Args[0]
		nprimes = instr.Call.Args[1]
		bits    = instr.Call.Args[2]
	)

	checkSecureRandomReader(pass, instr, random)

	checkBits(pass, instr, bits)

	checkNPrimesForBits(pass, instr, nprimes, bits)

	pass.Reportf(instr.Pos(), generateKeyMessage)
}

// checkGenerateKey checks if the [crypto/rsa.GenerateKey] function is being used securely.
func checkGenerateKey(pass *analysis.Pass, instr *ssa.Call) {
	var (
		random = instr.Call.Args[0]
		bits   = instr.Call.Args[1]
	)

	checkSecureRandomReader(pass, instr, random)

	checkBits(pass, instr, bits)
}

// checkEncryptPKCS1v15 checks if the [crypto/rsa.EncryptPKCS1v15] function is being used securely.
func checkEncryptPKCS1v15(pass *analysis.Pass, instr *ssa.Call) {
	checkSecureRandomReader(pass, instr, instr.Call.Args[0])

	pass.Reportf(instr.Pos(), oaepMessage)
}

// run is the entry point for the analysis pass, and will be called once for each package
// being analyzed. The SSA representation of the package is provided, and the analysis
// should return a result value and an error (which should be nil if the analysis succeeded).
func run(pass *analysis.Pass) (interface{}, error) {
	ir := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	for _, fn := range ir.SrcFuncs {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				switch instr := instr.(type) {
				case *ssa.Call:
					switch instr.Call.Value.String() {
					case generateMultiPrimeKey:
						checkGenerateMultiPrimeKey(pass, instr)
					case generateKey:
						checkGenerateKey(pass, instr)
					case encryptPKCS1v15:
						checkEncryptPKCS1v15(pass, instr)
					default:
						// fmt.Println(instr.Call.Value.String())
						continue
					}
				}
			}
		}
	}

	return nil, nil
}
