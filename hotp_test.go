package otp

import (
	"testing"
)

func Test_InitFail1(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Initialize of HOTP should have panicked")
		}
	}()
	NewDefaultHOTP("issuer", nil)
}

func Test_InitFail2(t *testing.T) {
	res := new(CounterBased)
	res.Algorithm = Algorithm(255)
	res.Digits = DigitMode(255)
	res.AccountStore = new(HOTPAccStore)
	res.Issuer = TestIssuer
	res.ensureInitialized()

	if res.Algorithm != SHA1 {
		t.Error("Setting the default algorithm failed")
	}
	if res.Digits != Dec6 {
		t.Error("Setting the default digit mode failed")
	}
}

// evtl die anderen beiden ensureInit fälle abdecken

type HOTPAccStore struct {
	val uint64
}

func (s *HOTPAccStore) CounterValue(a Account) uint64 {
	return s.val
}

func (s *HOTPAccStore) SetCounterValue(a Account, v uint64) {
	s.val = v
}

func Test_HOTP(t *testing.T) {
	a := new(HOTPAccStore)
	a.val = 0
	hotp := NewDefaultHOTP(TestIssuer, a)
	if hotp == nil {
		t.Error("HOTP should have been created")
	}
	if !hotp.IsValid(TestAccount, "755224", 0) || a.val != 1 {
		t.Error("HOTP calculation failed")
	}
	if !hotp.IsValid(TestAccount, "969429", DefaultCounterTolerance) || a.val != 4 {
		t.Error("HOTP calculation with tolerance failed")
	}
	if hotp.IsValid(TestAccount, "000000", 1000) {
		t.Error("HOTP Invalid Token failed")
	}
	a.val = 0

	if !hotp.IsValid(TestAccount, "755224", 0) || !hotp.IsValid(TestAccount, "287082", 0) || !hotp.IsValid(TestAccount, "359152", 0) ||
		!hotp.IsValid(TestAccount, "969429", 0) || !hotp.IsValid(TestAccount, "338314", 0) || !hotp.IsValid(TestAccount, "254676", 0) ||
		!hotp.IsValid(TestAccount, "287922", 0) || !hotp.IsValid(TestAccount, "162583", 0) || !hotp.IsValid(TestAccount, "399871", 0) ||
		!hotp.IsValid(TestAccount, "520489", 0) {
		t.Error("Calculation of first 10 HOTP values failed")
	}
}
