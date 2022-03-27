package ssha1

import (
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"testing"
)

type sumCase struct {
	plaintext         []byte
	salt              []byte
	expectedHexString string
}

func TestSum(t *testing.T) {
	sumCases := []sumCase{
		{[]byte("supercalifragilisticexpialidocious"), []byte("n4pggXWL"), "8eadde532169b6908034886be119c9f0ca61801e6e3470676758574c"},
		{[]byte("abcdefghijklmnopqrstuvwxyz"), []byte("K218iReB"), "4ced2536edce6706cccf0c14a10a939022f6b0614b32313869526542"},
	}

	for _, c := range sumCases {
		result, err := Sum(c.plaintext, c.salt)
		if err != nil {
			t.Errorf("method Sum() returned unexpected error: %e", err)
		}
		resultString := hex.EncodeToString(result)
		if resultString != c.expectedHexString {
			t.Errorf("result = %s; expected %s", resultString, c.expectedHexString)
		}
	}
}

type sizeCase struct {
	newMethod  string
	h          hash.Hash
	errFromNew error
	expected   int
}

func setUpSizeCases() []sizeCase {
	var c1 sizeCase
	c1.newMethod = "New()"
	c1.h, c1.errFromNew = New()
	c1.expected = sha1.Size + DefaultNumSaltBytes

	var c2 sizeCase
	c2.newMethod = "NewForSaltSize()"
	c2.h, c2.errFromNew = NewForSaltSize(32)
	c2.expected = sha1.Size + 32

	var c3 sizeCase
	salt1 := []byte("2cM6D2WitazRL5MD")
	c3.newMethod = "NewWithSalt()"
	c3.h, c3.errFromNew = NewWithSalt(salt1)
	c3.expected = sha1.Size + len(salt1)

	cases := make([]sizeCase, 0)
	cases = append(cases, c1, c2, c3)

	return cases
}

func TestSize(t *testing.T) {
	cases := setUpSizeCases()

	for _, c := range cases {
		if c.errFromNew != nil {
			t.Errorf("%s returned unexpected error: %e", c.newMethod, c.errFromNew)
		}
		if got := c.h.Size(); got != c.expected {
			t.Errorf("for test case %v: Size = %d; expected %d", c, got, c.expected)
		}
	}
}

type validateCase struct {
	ssha1HashString string
	sample          []byte
	expected        bool
	expectError     bool
}

func TestValidate(t *testing.T) {
	cases := []validateCase{
		// salt: "abcdefg"
		{"8417680c09644df743d7cea1366fbe13a31b2d5e61626364656667", []byte("1234567890"), true, false},
		// salt: "abcdefg"
		{"8417680c09644df743d7cea1366fbe13a31b2d5e61626364656667", []byte("123456789"), false, false},
		// salt: "x5yunfC]3rrjw*@VeBxNeW*oRp-PM>s*"
		{"f14713de1964843beae542b4f13024398549ac7d783579756e66435d3372726a772a40566542784e65572a6f52702d504d3e732a", []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."), true, false},
		// salt: "X"
		{"691beaac130a0be25dc517de4e6391334d3d0f3758", []byte("protean-pith-anodyne-accolade-snare"), true, false},
		// too short to be at least a SHA-1 hash
		{"520d41b29f891bbaccf31d", nil, false, true},
		// long enough to be at least a SHA-1 hash, but lacks at least 1 salt byte
		{"9ab50f27d4201db9b28483ba83c48ebafbb2aa17", nil, false, true},
	}

	for _, c := range cases {
		ssha1Hash, err := hex.DecodeString(c.ssha1HashString)
		if err != nil {
			t.Errorf("unable to convert hex string '%s' to []byte.", err)
		}

		result, err := Validate(ssha1Hash, c.sample)
		if c.expectError {
			if err == nil {
				t.Errorf("expected error but none returned for test case: %v", c)
			}
		} else if err != nil {
			t.Errorf("unexpected error (%e) for returned for test case: %v", err, c)
		}
		if result != c.expected {
			t.Errorf("validation test failed for test case %v", c)
		}
	}
}

func TestBlockSize(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Errorf("method New() returned unexpected error: %e", err)
	}
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d; expected %d", got, BlockSize)
	}
}
