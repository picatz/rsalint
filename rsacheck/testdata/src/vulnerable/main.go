package main

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/rand"
)

func main() {
	r := rand.New(rand.NewSource(0))

	privateKey, err := rsa.GenerateMultiPrimeKey(r, 9, 1024) // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use 2048 bits or greater" "for 1024 bits 3 is the max number of primes to use" "use rsa.GenerateKey instead of rsa.GenerateMultiPrimeKey"
	if err != nil {
		panic(err)
	}

	privateKey, err = rsa.GenerateKey(r, 1024) // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use 2048 bits or greater"
	if err != nil {
		panic(err)
	}

	msg := []byte("Thu Dec 19 18:06:16 EST 2013\n")

	sig, err := rsa.SignPKCS1v15(nil, privateKey, crypto.Hash(0), msg)
	if err != nil {
		panic(err)
	}
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.Hash(0), msg, sig); err != nil {
		panic(err)
	}

	eMesg, err := rsa.EncryptPKCS1v15(r, &privateKey.PublicKey, msg) // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use rsa.EncryptOAEP instead of rsa.EncryptPKCS1v15"
	if err != nil {
		panic(err)
	}

	fmt.Println(eMesg)
}
