package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// constants defining which hash algorithm should be used.
type Algorithm byte

const (
	// (default)
	SHA1 Algorithm = iota
	SHA256
	SHA512
	MD5
)

func (a Algorithm) string() string {
	switch a {
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	case MD5:
		return "MD5"
	default:
		return "SHA1"
	}
}

func (a Algorithm) newHash() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	case MD5:
		return md5.New
	default:
		return sha1.New
	}
}
