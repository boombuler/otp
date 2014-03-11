// One Time Password generator compatible with RFC 6238 and RFC 4226
package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

const minimumKeyLength int = 10

func calcOTP(secret []byte, iterationNumber uint64, digits DigitMode, hashFn func() hash.Hash) string {
	if len(secret) < minimumKeyLength {
		panic("Key to short")
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, iterationNumber)

	hasher := hmac.New(hashFn, secret)
	hasher.Write(counter)
	hash := hasher.Sum(nil)

	offset := hash[len(hash)-1] & 0xf
	password := int32(binary.BigEndian.Uint32(hash[offset:]) & 0x7FFFFFFF)
	password = password % digits.modulo()

	return digits.formatOutput(password)
}
