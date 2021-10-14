package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"math/rand"
)

func main() {
	r := rand.New(rand.NewSource(0))

	privateKey, err := rsa.GenerateMultiPrimeKey(r, 9, 1024) // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use 2048 bits or greater" "for 1024 bits 3 is the max number of primes to use"
	if err != nil {
		panic(err)
	}

	privateKey, err = rsa.GenerateKey(r, 1024) // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use 2048 bits or greater"
	if err != nil {
		panic(err)
	}

	msg := []byte("Thu Dec 19 18:06:16 EST 2013\n")

	sig, err := rsa.SignPKCS1v15(nil, privateKey, crypto.Hash(0), msg) // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "do not use nil for entropy source to perform blinding to avoid timing side-channel attacks" "use SHA 256/512 for hash when signing" "use rsa.SignPSS instead of rsa.SignPKCS1v15"
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

	buf := bytes.NewBuffer([]byte("1234"))

	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, nil)            // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use a session key of 16 bytes or greater"
	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, []byte("1234")) // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use a session key of 16 bytes or greater"
	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, []byte{0xff})   // want "use the crypto/rand.Reader for a cryptographically secure random number generator" "use a session key of 16 bytes or greater"
	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, buf.Bytes())    // want "use the crypto/rand.Reader for a cryptographically secure random number generator"
	// -------------------------------------------------------^ buff check not implemented
	if err != nil {
		panic(err)
	}

	label := []byte("example")

	encMesg, err := rsa.EncryptOAEP(sha1.New(), r, &privateKey.PublicKey, msg, label)
	if err != nil {
		panic(err)
	}

	decMesg, err := rsa.DecryptOAEP(sha1.New(), nil, privateKey, encMesg, label) // want "use SHA 256/512 for hash when decrypting or encrypting" "use the crypto/rand.Reader for a cryptographically secure random number generator" "do not use nil for entropy source to perform blinding to avoid timing side-channel attacks"
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(msg, decMesg) {
		panic(fmt.Sprintf("failed dec: exp: %q got: %q", string(msg), string(decMesg)))
	}
}
