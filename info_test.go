package otp

import (
	"net/url"
	"testing"
	"time"
)

func Test_TOTPAuthUri(t *testing.T) {
	var TestIssuer = "test"
	res := NewDefaultTOTP(TestIssuer)

	uri, err := url.Parse(res.OTPAuthUri(TestAccount))
	if err != nil {
		t.Error(err)
	} else {
		if uri.Scheme != "otpauth" {
			t.Errorf("invalid uri scheme: %s", uri.Scheme)
		}
		if uri.Host != "totp" {
			t.Errorf("invalid host %s", uri.Host)
		}
		if uri.Path != "/"+string(TestAccount) {
			t.Errorf("invalid path: %s", uri.Path)
		}
		params := uri.Query()
		if p := params.Get("secret"); p != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
			t.Errorf("invalid secret: %s", p)
		}
		if p := params.Get("issuer"); p != TestIssuer {
			t.Errorf("invalid issuer: %s", p)
		}
		if len(params) != 2 {
			t.Error("to many parameters")
		}
	}

	res.Algorithm = MD5
	res.Digits = Dec8
	res.Period = 20 * time.Second
	uri, err = url.Parse(res.OTPAuthUri(TestAccount))
	if err != nil {
		t.Error(err)
	} else {
		params := uri.Query()
		if p := params.Get("algorithm"); p != "MD5" {
			t.Errorf("invalid algorithmn: %s", p)
		}
		if p := params.Get("digits"); p != "8" {
			t.Errorf("invalid digits: %s", p)
		}
		if p := params.Get("period"); p != "20" {
			t.Errorf("invalid period: %s", p)
		}
		if len(params) != 5 { // digits, algorithm, period, secret, issuer
			t.Error("to many parameters")
		}
	}
}

func Test_HOTPAuthUri(t *testing.T) {
	a := new(HOTPAccStore)
	a.val = 1000
	hotp := NewDefaultHOTP(TestIssuer, a)
	uri, err := url.Parse(hotp.OTPAuthUri(TestAccount))
	if err != nil {
		t.Error(err)
	} else {
		if uri.Scheme != "otpauth" {
			t.Errorf("invalid uri scheme: %s", uri.Scheme)
		}
		if uri.Host != "hotp" {
			t.Errorf("invalid host %s", uri.Host)
		}
		if uri.Path != "/"+string(TestAccount) {
			t.Errorf("invalid path: %s", uri.Path)
		}
		params := uri.Query()
		if p := params.Get("secret"); p != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
			t.Errorf("invalid secret: %s", p)
		}
		if p := params.Get("issuer"); p != TestIssuer {
			t.Errorf("invalid issuer: %s", p)
		}
		if p := params.Get("counter"); p != "1000" {
			t.Errorf("invalid counter: %s", p)
		}
		if len(params) != 3 {
			t.Error("to many parameters")
		}
	}

}
