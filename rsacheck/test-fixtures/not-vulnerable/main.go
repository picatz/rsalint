package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	msg := []byte("Thu Dec 19 18:06:16 EST 2013\n")

	hashed := sha256.Sum256(msg)

	sig, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		panic(err)
	}
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, msg, sig); err != nil {
		panic(err)
	}
}
