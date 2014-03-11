package otp

import (
	"encoding/base32"
	"net/url"
	"strconv"
)

// An user account which can be used to calculate an OTP.
type Account interface {
	// returns the shared secret. The secret must be at least 10 bytes long
	Secret() []byte
	// returns a label for this account.
	Label() string
}

type authUriModeInfo interface {
	string() string
	addOTPAuthUriParams(params url.Values, account Account)
}

// General information about the otp calculation
type Info struct {
	// an Issuer (site name etc.)
	Issuer string
	// Number of digits. Can be Dec6 or Dec8
	Digits DigitMode
	// The hashing algorithm used to calculate the otp. default is SHA1
	Algorithm Algorithm
}

func (otp Info) getOTPAuthUri(mode authUriModeInfo, account Account) string {
	accName := account.Label()

	params := url.Values{}
	params.Add("secret", base32.StdEncoding.EncodeToString(account.Secret()))

	if otp.Issuer != "" {
		params.Add("issuer", otp.Issuer)
	}
	if otp.Algorithm != SHA1 {
		params.Add("algorithm", otp.Algorithm.string())
	}
	if otp.Digits != Dec6 {
		params.Add("digits", strconv.Itoa(int(otp.Digits)))
	}
	mode.addOTPAuthUriParams(params, account)

	result := new(url.URL)
	result.Scheme = "otpauth"
	result.Host = mode.string()
	result.Path = accName
	result.RawQuery = params.Encode()

	return result.String()
}
