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

	privateKey, err := rsa.GenerateMultiPrimeKey(r, 9, 1024)
	if err != nil {
		panic(err)
	}

	privateKey, err = rsa.GenerateKey(r, 1024)
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

	eMesg, err := rsa.EncryptPKCS1v15(r, &privateKey.PublicKey, msg)
	if err != nil {
		panic(err)
	}

	buf := bytes.NewBuffer([]byte("1234"))

	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, nil)
	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, []byte("1234"))
	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, []byte{0xff})
	err = rsa.DecryptPKCS1v15SessionKey(r, privateKey, eMesg, buf.Bytes()) // check not implemented
	if err != nil {
		panic(err)
	}

	label := []byte("example")

	encMesg, err := rsa.EncryptOAEP(sha1.New(), r, &privateKey.PublicKey, msg, label)
	if err != nil {
		panic(err)
	}

	decMesg, err := rsa.DecryptOAEP(sha1.New(), nil, privateKey, encMesg, label)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(msg, decMesg) {
		panic(fmt.Sprintf("failed dec: exp: %q got: %q", string(msg), string(decMesg)))
	}
}
