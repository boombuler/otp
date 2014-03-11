package otp

import (
	"testing"
	"time"
)

const TestIssuer string = "test"

func Test_NewDefaultTOTP(t *testing.T) {
	res := NewDefaultTOTP(TestIssuer)
	if res == nil ||
		res.Issuer != TestIssuer ||
		res.string() != "totp" ||
		res.Algorithm != SHA1 ||
		res.Digits != Dec6 ||
		res.GetTimeFn == nil ||
		res.Period != DefaultTimePeriod {
		t.Fail()
	}

	res = new(TimeBased)
	res.Algorithm = Algorithm(255)
	res.Digits = DigitMode(255)
	res.Issuer = TestIssuer
	res.Period = -100 * time.Second
	res.ensureInitialized()
	if res.Issuer != TestIssuer ||
		res.string() != "totp" ||
		res.Algorithm != SHA1 ||
		res.Digits != Dec6 ||
		res.GetTimeFn == nil ||
		res.Period != DefaultTimePeriod {
		t.Fail()
	}

	res = new(TimeBased)
	res.GetTimeFn = func() time.Time {
		return time.Unix(1111111111, 0)
	}
	if res.CurrentOTP(TestAccount) != "050471" {
		t.Fail()
	}
}

func Test_IsValid(t *testing.T) {
	var correctTime time.Time = time.Unix(1111111111, 0)
	var correctResult string = "050471"
	var incorrectResult string = "123456"

	getGenerator := func(tm time.Time) *TimeBased {
		return &TimeBased{
			Info: Info{Digits: Dec6, Algorithm: SHA1},
			GetTimeFn: func() time.Time {
				return tm
			},
			Period: 30 * time.Second,
		}
	}

	gen := getGenerator(correctTime)
	if !gen.IsValid(TestAccount, correctResult, 0) || gen.IsValid(TestAccount, incorrectResult, 0) {
		t.Fail()
	}
	if !gen.IsValid(TestAccount, correctResult, -100*time.Second) {
		t.Fail()
	}

	gen = getGenerator(correctTime.Add(-10 * time.Second))
	if gen.IsValid(TestAccount, correctResult, DefaultTimeTolerance) {
		t.Fail()
	}
	if !gen.IsValid(TestAccount, correctResult, 15*time.Second) {
		t.Fail()
	}
	gen = getGenerator(correctTime.Add(40 * time.Second))
	if gen.IsValid(TestAccount, correctResult, DefaultTimeTolerance) {
		t.Fail()
	}
	if !gen.IsValid(TestAccount, correctResult, 15*time.Second) {
		t.Fail()
	}
}

func Test_getIteration(t *testing.T) {
	if getIteration(time.Unix(100, 0), 10.0) != 10 {
		t.Fail()
	}
	if getIteration(time.Unix(300, 0), 0) != 10 {
		t.Fail()
	}
	if getIteration(time.Unix(100, 0), -10.0) != 10 {
		t.Fail()
	}
}
