# rsalint

 🕵️‍♀️ Linter for the [`crypto/rsa`](https://golang.org/pkg/crypto/rsa/) package.

## Install

```console
$ go install github.com/picatz/rsalint/cmd/rsalint@latest
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

- Weak entropy source (not using `crypto/rand.Reader`).
- Weak number of bits (less than `2048`, and not a multiple of `8`).
- Weak number of primes for the given number of bits.
- Deprecated functions (`rsa.GenerateMultiPrimeKey`).
- Insecure encryption schemes (`rsa.EncryptPKCS1v15`).

## Usage

```console
$ rsalint ./path/to/vulnerable/code/...
./path/to/vulnerable/code/main.go:10:37: use the crypto/rand.Reader instead for a cryptographically secure random number generator
./path/to/vulnerable/code/main.go:10:66: use 2048 bits or greater
```
