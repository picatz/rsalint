# rsalint

 🕵️‍♀️Golang [linter](https://en.wikipedia.org/wiki/Lint_(software)) for the [`crypto/rsa`](https://golang.org/pkg/crypto/rsa/) package.

## Install

```console
$ go get -u -v github.com/picatz/rsalint/cmd/...
...
```

## Vulnerable Implementation

```go
package main

import (
    "crypto/rsa"
    "fmt"
    "math/rand"
)

func main() {
    privateKey, err := rsa.GenerateKey(rand.New(rand.NewSource(0)), 1024)
    if err != nil {
        panic(err)
    }
    fmt.Println(privateKey)
}
```

`rsalint` can identify a number of potential security problems:

* Using an insecure source of entropy using `math/rand` ( always use `crypto/rand` ).
* Using an insecure hash function ( not SHA256 or SHA512 ).
* Generating an RSA key pair using an insecure number of bits ( always use `>= 2048` ).
* Using potentially insecure signing function [`rsa.SignPKCS1v15`](https://golang.org/pkg/crypto/rsa/#SignPKCS1v15) instead of [`rsa.SignPSS`](https://golang.org/pkg/crypto/rsa/#SignPSS).
* Using potentially insecure signing function [`rsa.EncryptPKCS1v15`](https://golang.org/pkg/crypto/rsa/#EncryptPKCS1v15) instead of [`rsa.EncryptOAEP`](https://golang.org/pkg/crypto/rsa/#EncryptOAEP).
* Using an insecure value for multi-prime keys for various bit sizes.
* Using an insecure PKCS1v15 session key size.
* Not using RSA blinding leading to possible timing side-channel attacks.


## Usage

```console
$ rsalint ./path/to/vulnerable/code/...
./path/to/vulnerable/code/main.go:10:37: use the crypto/rand.Reader instead for a cryptographically secure random number generator
./path/to/vulnerable/code/main.go:10:66: always use 2048 bits or greater
```
