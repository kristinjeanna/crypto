# github.com/kristinjeanna/crypto/ssha1

Package ssha1 provides a salted SHA-1 implementation. The API can be used
in a couple of ways, pick one that suits your needs.

Use the provided helper functions, `Sum()` and `Validate()` to calculate and
validate salted SHA-1 hashes.

To calculate a hash:

```go
plaintext := []byte("supercalifragilisticexpialidocious")
salt := []byte("n4pggXWL")

ssha1Hash, err := Sum(plaintext, salt)
if err != nil {
    panic("an error occurred while calculating the hash")
}
```

Likewise, to validate a hash:

```go
result, err := Validate(ssha1Hash, plaintext)
if err != nil {
    panic("an error occurred while validating the hash")
}
if !result {
    fmt.Println("validation failed")
}
```

As an alternative, you can use the provided `hash.Hash` implementation. The
NewXxx functions allow you to create instances.

The `New()`function creates an instance using a random salt generated via the
`crypto/rand` package:

```go
h, err := New() // default salt size is 20
```

The `NewWithSalt()` function creates an instance with a specified salt:

```go
h, err := NewWithSalt([]byte("R*w.5Vmo"))
```

Lastly, the `NewForSaltSize()` function creates an instance with a random
salt (via the `crypto/rand` package) of a specified size:

```go
h, err := NewForSaltSize(32)
```

Note that the minimum salt size permitted is 1 byte.
