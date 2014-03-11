package otp

import (
	"net/url"
	"strconv"
)

// Counter base one time password generator
type CounterBased struct {
	// General calculation information
	Info
	// Keeps track of the current counter Values for the Accounts
	AccountStore
}

// Interface to store current counter values for HOTP generators.
type AccountStore interface {
	// returns the current counter value for the given account
	CounterValue(account Account) uint64
	// stores a new counter value for the given account
	SetCounterValue(account Account, counter uint64)
}

// Default tolerance value for HOTP generators
const DefaultCounterTolerance = 5

func (cbi *CounterBased) ensureInitialized() {
	if cbi.AccountStore == nil {
		panic("AccountStore has to be set!")
	}
	if cbi.Digits != Dec6 && cbi.Digits != Dec8 {
		cbi.Digits = Dec6
	}
	if cbi.Algorithm < SHA1 || cbi.Algorithm > MD5 {
		cbi.Algorithm = SHA1
	}
}

// checks if the given otp is valid. if the otp is wrong it also checks the next few otps
// the tolerance argument controls how many additional otps are checked.
func (cbi *CounterBased) IsValid(account Account, otp string, tolerance uint64) bool {
	cbi.ensureInitialized()

	secret := account.Secret()
	hash := cbi.Algorithm.newHash()
	digits := cbi.Digits

	firstIt := cbi.CounterValue(account)
	lastIt := firstIt + tolerance

	for it := firstIt; it <= lastIt; it++ {
		if otp == calcOTP(secret, it, digits, hash) {
			cbi.SetCounterValue(account, it+1)
			return true
		}
	}
	return false
}

func (cbi *CounterBased) addOTPAuthUriParams(params url.Values, account Account) {
	cbi.ensureInitialized()
	cntValue := cbi.CounterValue(account)
	params.Add("counter", strconv.FormatUint(cntValue, 10))

}

func (cbi *CounterBased) string() string {
	return "hotp"
}

// returns an uri which could be provided to the user via qr code.
// it contains all necessary information to setup the otp generator
func (cbi *CounterBased) OTPAuthUri(account Account) string {
	cbi.ensureInitialized()
	return cbi.Info.getOTPAuthUri(cbi, account)
}

// returns a new counterbased otp generator for the given issuer
// (6 digits, SHA1)
func NewDefaultHOTP(issuer string, accountStore AccountStore) *CounterBased {
	cbi := new(CounterBased)
	cbi.Issuer = issuer
	cbi.AccountStore = accountStore
	cbi.ensureInitialized()
	return cbi
}
