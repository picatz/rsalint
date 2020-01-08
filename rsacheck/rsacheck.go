// Package rsacheck defines an Analyzer to report insecure usage of the "crypto/rsa" package.
package rsacheck

import (
	"fmt"
	"go/ast"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// TODO: improve lint messages
const (
	randSourceLintMessage     = "use the crypto/rand.Reader instead for a cryptographically secure random number generator"
	numberOfbitsLintMessage   = "always use 2048 bits or greater"
	numberOfPrimesLintMessage = "the reccomended number of primes for %v bits is %v"
	hashLintSigningMessage    = "use SHA 256/512 for hash when signing"
	hashLintEncDecMessage     = "use SHA 256/512 for hash when decrypting or encrypting"
	keySizeLintcMessage       = "use a session key size of 16 bytes or greater"
	signingLintMessage        = "use rsa.SignPSS instead of rsa.SignPKCS1v15"
	encryptingLintMessage     = "use rsa.EncryptOAEP instead of rsa.EncryptPKCS1v15"
	blidingLintMessage        = "do not use nil for entropy source to perform blinding to avoid timing side-channel attacks"
)

var Analyzer = &analysis.Analyzer{
	Name:     "rsalint",
	Doc:      "report insecure usage of the \"crypto/rsa\" package",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	var (
		isOfSelectorExprType = func(typeStr string, e ast.Expr) bool {
			se, ok := e.(*ast.SelectorExpr)
			if ok {
				return fmt.Sprintf("%v.%v", se.X, se.Sel) == typeStr
			}
			return false
		}

		// check if the entropy argument isn't nil to use
		// blinding to avoid timing side-channel attacks.
		checkBlindKeyOp = func(e ast.Expr) {
			if pass.TypesInfo.TypeOf(e).String() == "untyped nil" {
				pass.Reportf(e.Pos(), blidingLintMessage)
			}
		}

		// check if the first argument isn't crypto.Rand
		checkSecureEntropySource = func(e ast.Expr) {
			if !isOfSelectorExprType("rand.Reader", e) {
				pass.Reportf(e.Pos(), randSourceLintMessage)
			}
		}

		// check if the second argument is greater than or equal to 2048 bits
		checkSecureNumberOfBits = func(e ast.Expr) {
			bits, err := strconv.Atoi(pass.TypesInfo.Types[e].Value.String())
			if err == nil {
				if bits < 2048 {
					pass.Reportf(e.Pos(), numberOfbitsLintMessage)
				}
			}
		}

		// check if the second argument is greater than or equal to 2048 bits
		checkSecureNumberOfPrimesForBits = func(e1, e2 ast.Expr) {
			nprimes := pass.TypesInfo.Types[e1].Value.String()
			bits := pass.TypesInfo.Types[e2].Value.String()
			if recMaxNum, ok := recommendedMaxNumberOfPrimesForBitsTable[bits]; ok {
				if recMaxNum != nprimes {
					pass.Reportf(e1.Pos(), numberOfPrimesLintMessage, bits, recMaxNum)
				}
			}
		}

		// check if SHA 256 or 512 is being used
		checkSecureHashAlgo = func(e ast.Expr) {
			// check if the third argument is using SHA256 ( crypto.Hash value 5 ).
			hashValue := fmt.Sprintf("%v", pass.TypesInfo.Types[e].Value)
			if hashValue != "7" && hashValue != "5" {
				pass.Reportf(e.Pos(), hashLintSigningMessage)
			}
		}

		// check if "crypto/sha256" or "crypto/sha512" is being used
		checkSecureHashFunc = func(e ast.Expr) {
			ce, ok := e.(*ast.CallExpr)
			if ok {
				se, ok := ce.Fun.(*ast.SelectorExpr)
				if ok {
					if !isOfSelectorExprType("sha256.New", se) && !isOfSelectorExprType("sha512.New", se) {
						pass.Reportf(ce.Pos(), hashLintEncDecMessage)
					}
				}
			}
		}

		// check the session key size for PKCS#1 v1.5
		checkPKCS1v15SessionKeySize = func(e ast.Expr) {
			if pass.TypesInfo.TypeOf(e).String() == "untyped nil" {
				pass.Reportf(e.Pos(), keySizeLintcMessage)
			} else if pass.TypesInfo.TypeOf(e).String() == "[]byte" {
				switch t := e.(type) {
				case *ast.CallExpr:
					// using []byte("style call")
					if pass.TypesInfo.TypeOf(t.Fun).String() == "[]byte" {
						s, err := strconv.Unquote(pass.TypesInfo.Types[t.Args[0]].Value.String())
						if err == nil {
							if len(s) < 16 {
								pass.Reportf(t.Pos(), keySizeLintcMessage)
							}
						}
					} else if pass.TypesInfo.TypeOf(t.Fun).String() == "func() []byte" {
						// TODO: add more robust check for bytes.Buffer style calls
						// to generate key sizes. Need to check if less than 16 bytes
						// like the []byte("style call") which can inspect the given string
						// ex, ok := t.Fun.(*ast.SelectorExpr)
						// if ok {
						// 	pass.Reportf(t.Pos(), "DEBUG: %v", ex)
						// }
					}
				case *ast.CompositeLit:
					if t.Elts == nil || len(t.Elts) < 16 {
						pass.Reportf(t.Pos(), keySizeLintcMessage)
					}
				default:
					pass.Reportf(e.Pos(), "TRACE: %v", pass.TypesInfo.TypeOf(t))
				}
			}
		}
	)

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		ce := n.(*ast.CallExpr)
		se, ok := ce.Fun.(*ast.SelectorExpr)
		if ok {
			// if generating a key
			if isOfSelectorExprType("rsa.GenerateKey", se) {
				checkSecureEntropySource(ce.Args[0])
				checkSecureNumberOfBits(ce.Args[1])
				return
			}

			if isOfSelectorExprType("rsa.GenerateMultiPrimeKey", se) {
				checkSecureEntropySource(ce.Args[0])
				checkSecureNumberOfBits(ce.Args[2])
				checkSecureNumberOfPrimesForBits(ce.Args[1], ce.Args[2])
				return
			}

			// if decrypting a message with OAEP
			if isOfSelectorExprType("rsa.DecryptOAEP", se) {
				checkSecureHashFunc(ce.Args[0])
				checkSecureEntropySource(ce.Args[1])
				checkBlindKeyOp(ce.Args[1])
				return
			}

			// if signing a message with PKCS1 v 1.5
			if isOfSelectorExprType("rsa.SignPKCS1v15", se) {
				checkSecureEntropySource(ce.Args[0])
				checkBlindKeyOp(ce.Args[0])
				checkSecureHashAlgo(ce.Args[2])
				pass.Reportf(se.Pos(), signingLintMessage)
				return
			}

			// if decrypting a PKCS1 v 1.5 session key
			if isOfSelectorExprType("rsa.DecryptPKCS1v15SessionKey", se) {
				checkBlindKeyOp(ce.Args[0])
				checkPKCS1v15SessionKeySize(ce.Args[3])
				return
			}

			// if encrypting a message with PKCS1 v 1.5
			if isOfSelectorExprType("rsa.EncryptPKCS1v15", se) {
				checkSecureEntropySource(ce.Args[0])
				pass.Reportf(se.Pos(), encryptingLintMessage)
				return
			}
		}
	})
	return nil, nil
}

// http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
// num-bits -> rec-num-of-primes
var recommendedMaxNumberOfPrimesForBitsTable = map[string]string{
	"1024": "3",
	"2048": "3",
	"4096": "4",
	"8192": "5",
}
