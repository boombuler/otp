package otp

import (
	"testing"
	"time"
)

type SecretOnlyAccount string

const TestAccount SecretOnlyAccount = "12345678901234567890"

func (s SecretOnlyAccount) Secret() []byte {
	return []byte(s)
}
func (s SecretOnlyAccount) Label() string {
	return string(s)
}

func Test_ShortKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("short key panic expected")
		}
	}()
	calcOTP([]byte("123"), 1, Dec6, SHA1.newHash())
}

func Test_calcTOTP(t *testing.T) {
	tests := map[Algorithm]map[int64]string{
		SHA1: {
			1111111111: "050471",
			1234567890: "005924",
			2000000000: "279037",
		},
		SHA256: {
			1111111111: "584430",
			1234567890: "829826",
			2000000000: "428693",
		},
		SHA512: {
			1111111111: "380122",
			1234567890: "671578",
			2000000000: "464532",
		},
		MD5: {
			1111111111: "275841",
			1234567890: "280616",
			2000000000: "090484",
		},
	}

	for a, atests := range tests {
		for tm, result := range atests {
			info := &TimeBased{
				Info: Info{
					Digits:    Dec6,
					Algorithm: a,
				},
				GetTimeFn: func() time.Time {
					return time.Unix(tm, 0)
				},
				Period: 30 * time.Second,
			}
			if info.CurrentOTP(TestAccount) != result {
				t.Errorf("Failed on Algorithm %s for time %d ", a, uint64(tm))
			}
		}
		t.Logf("Algorithm %s passed.", a)
	}
}
