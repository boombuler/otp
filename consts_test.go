package otp

import (
	"testing"
)

func Test_AlgorithmStringer(t *testing.T) {
	for alg, str := range map[Algorithm]string{
		SHA1:   "SHA1",
		SHA256: "SHA256",
		SHA512: "SHA512",
		MD5:    "MD5",
	} {
		if alg.string() != str {
			t.Errorf("Invalid String() implementation for Algorithm '%s'", str)
		}
	}
}

func Test_AlgorithmGetHash(t *testing.T) {
	for _, alg := range []Algorithm{SHA1, SHA256, SHA512, MD5} {
		if alg.newHash() == nil {
			t.Errorf("Missing getHash() implementation for Algorithm '%s'", alg)
		}
	}
}
