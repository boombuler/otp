package otp

import (
	"math"
	"net/url"
	"strconv"
	"time"
)

// Time base one time password generator
type TimeBased struct {
	// General calculation information
	Info
	// a function which retrieves the time which is used for calculation
	GetTimeFn func() time.Time
	// indicates how long a single otp is valid.
	Period time.Duration
}

func (tbi *TimeBased) ensureInitialized() {
	if tbi.GetTimeFn == nil {
		tbi.GetTimeFn = time.Now
	}
	if tbi.Period <= 0 {
		tbi.Period = DefaultTimePeriod
	}
	if tbi.Digits != Dec6 && tbi.Digits != Dec8 {
		tbi.Digits = Dec6
	}
	if tbi.Algorithm < SHA1 || tbi.Algorithm > MD5 {
		tbi.Algorithm = SHA1
	}
}

// the default time period an otp is valid
const DefaultTimePeriod time.Duration = 30 * time.Second

// the default tolerance when checking a otp
const DefaultTimeTolerance time.Duration = 3 * time.Second

// checks if the given otp is valid. also takes some tolerance into account.
// a tolerance might be usefull for network latency etc.
func (tbi *TimeBased) IsValid(account Account, otp string, tolerance time.Duration) bool {
	tbi.ensureInitialized()
	if tolerance < 0 {
		tolerance = -tolerance
	}

	now := tbi.GetTimeFn()
	period := tbi.Period.Seconds()
	secret := account.Secret()
	hash := tbi.Algorithm.newHash()
	digits := tbi.Digits

	firstIt := getIteration(now.Add(-tolerance), period)
	lastIt := getIteration(now.Add(+tolerance), period)

	for it := firstIt; it <= lastIt; it++ {
		if otp == calcOTP(secret, it, digits, hash) {
			return true
		}
	}
	return false
}

// calculates the current otp for the given account
func (tbi *TimeBased) CurrentOTP(account Account) string {
	tbi.ensureInitialized()
	return calcOTP(account.Secret(),
		getIteration(tbi.GetTimeFn(), tbi.Period.Seconds()),
		tbi.Digits,
		tbi.Algorithm.newHash())
}

func getIteration(t time.Time, period float64) uint64 {
	unixTime := uint64(t.Unix())
	pSeconds := uint64(math.Abs(period))

	if pSeconds == 0 {
		pSeconds = uint64(DefaultTimePeriod.Seconds())
	}
	return unixTime / pSeconds
}

func (tbi *TimeBased) addOTPAuthUriParams(params url.Values, account Account) {
	tbi.ensureInitialized()
	if tbi.Period != DefaultTimePeriod {
		params.Add("period", strconv.Itoa(int(tbi.Period.Seconds())))
	}
}

func (tbi *TimeBased) string() string {
	return "totp"
}

// returns an uri which could be provided to the user via qr code.
// it contains all necessary information to setup the otp generator
func (tbi *TimeBased) OTPAuthUri(account Account) string {
	tbi.ensureInitialized()
	return tbi.Info.getOTPAuthUri(tbi, account)
}

// returns a new timebased otp generator for the given issuer
// (6 digits, SHA1, based on current system time, every 30 seconds)
func NewDefaultTOTP(issuer string) *TimeBased {
	tbi := new(TimeBased)
	tbi.Issuer = issuer
	tbi.ensureInitialized()
	return tbi
}
