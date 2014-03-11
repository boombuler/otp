package otp

import (
	"math"
	"strconv"
)

// indicating the number of digits used for OTP generation
type DigitMode byte

const (
	// Decimal 6 digits
	Dec6 DigitMode = 6
	// Decimal 8 digits
	Dec8 DigitMode = 8
)

func (dm DigitMode) modulo() int32 {
	return int32(math.Pow(10, float64(byte(dm))))
}

func (dm DigitMode) formatOutput(password int32) string {
	digits := int(dm)

	passwordTxt := []byte(strconv.Itoa(int(password)))
	if len(passwordTxt) > digits {
		return ""
	}

	if len(passwordTxt) == digits {
		return string(passwordTxt)
	}

	result := make([]byte, digits-len(passwordTxt), digits)
	for i, _ := range result {
		result[i] = '0'
	}
	return string(append(result, passwordTxt...))
}
