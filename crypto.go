package crypto

import (
	"fmt"
	"hash"
)

type Hash interface {
	hash.Hash
	fmt.Stringer

	HexString() string
}
