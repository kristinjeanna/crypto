package ssha1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"github.com/kristinjeanna/crypto"
)

const (
	// DefaultNumSaltBytes specifies the default number of salt bytes
	// used when creating via New().
	DefaultNumSaltBytes int = 20

	// MinSaltBytes specifies the minimum allowed number of salt bytes.
	MinSaltBytes int = 1

	// BlockSize specifies the block size of the SHA-1 hash in bytes.
	BlockSize = sha1.BlockSize

	outputFmt string = "{SSHA}%s"

	errMsgSaltTooShort       string = "invalid salt length, must be at least 1 byte"
	errMsgSliceTooShortSha1  string = "slice too short for a SHA-1 hash"
	errMsgSliceTooShortSsha1 string = "slice too short to be a SSHA1 hash"
)

// New returns a new hash.Hash  with the default salt size (20 bytes).
// The salt will be generated using the crypto/rand package.
func New() (crypto.Hash, error) {
	d := new(digest)
	d.Reset()
	d.salt = make([]byte, DefaultNumSaltBytes)
	_, err := rand.Read(d.salt)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// NewWithSalt returns a new hash.Hash with the specified salt.
// Salt size must be 1 or greater.
func NewWithSalt(salt []byte) (crypto.Hash, error) {
	if len(salt) < MinSaltBytes {
		return nil, errors.New(errMsgSaltTooShort)
	}
	d := new(digest)
	d.Reset()
	d.salt = salt
	return d, nil
}

// NewForSaltSize returns a new hash.Hash with the specified salt size.
// Salt size must be 1 or greater. The salt will be generated using the
// crypto/rand package.
func NewForSaltSize(numSaltBytes int) (crypto.Hash, error) {
	if numSaltBytes < MinSaltBytes {
		return nil, errors.New(errMsgSaltTooShort)
	}
	d := new(digest)
	d.Reset()
	d.salt = make([]byte, numSaltBytes)
	_, err := rand.Read(d.salt)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Sum returns the SSHA1 checksum of the data.
func Sum(data, salt []byte) ([]byte, error) {
	var d hash.Hash
	if salt == nil {
		d0, err := New()
		if err != nil {
			return nil, err
		}
		d = d0
	} else {
		d0, err := NewWithSalt(salt)
		if err != nil {
			return nil, err
		}
		d = d0
	}

	d.Write(data)
	return d.Sum(nil), nil
}

// Validate returns true if the SSHA1 hash of the sample matches the
// specified SSHA1 hash; false, otherwise.
func Validate(ssha1Hash, sample []byte) (bool, error) {
	length := len(ssha1Hash)
	if length < sha1.Size {
		return false, errors.New(errMsgSliceTooShortSha1)
	}

	saltSize := length - sha1.Size
	if saltSize == 0 {
		return false, errors.New(errMsgSliceTooShortSsha1)
	}

	salt := ssha1Hash[length-saltSize:]
	d, err := NewWithSalt(salt)
	if err != nil {
		return false, err
	}

	d.Write(sample)
	result := d.Sum(nil)

	return bytes.Equal(ssha1Hash, result), nil
}

// #########################################################

type digest struct {
	internal []byte
	salt     []byte
}

// Size returns the number of bytes Sum will return.
func (d *digest) Size() int { return sha1.Size + len(d.salt) } // hash.Hash interface

// BlockSize returns the hash's underlying block size.
func (d *digest) BlockSize() int { return BlockSize } // hash.Hash interface

// Reset resets the Hash to its initial state. The salt will remain unchanged.
func (d *digest) Reset() { // hash.Hash interface
	d.internal = make([]byte, 0)
}

// Write adds more data to the running hash.
// It never returns an error.
func (d *digest) Write(p []byte) (int, error) { // io.Writer interface
	d.internal = append(d.internal, p...)
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(in []byte) []byte { // hash.Hash interface
	tmp := append(d.internal, d.salt...)
	sum := sha1.Sum(tmp)
	tmp = append(sum[:], d.salt...)
	return append(in, tmp...)
}

// String returns the base-64 encoded string representation of
// the SSHA1 sum, prefixed with "{SSHA}".
func (d *digest) String() string { // fmt.Stringer interface
	sum := d.Sum(nil)
	return fmt.Sprintf(outputFmt, base64.StdEncoding.EncodeToString(sum))
}

// HexString returns the SSHA1 sum as a hexadecimal string
func (d *digest) HexString() string { // crypto.Hash interface
	sum := d.Sum(nil)
	return hex.EncodeToString(sum)
}
