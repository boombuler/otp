package otp

import (
	"testing"
)

func Test_Modulo(t *testing.T) {
	if Dec6.modulo() != 1000000 {
		t.Fail()
	}
	if Dec8.modulo() != 100000000 {
		t.Fail()
	}
}

func Test_FormatOutput(t *testing.T) {
	all_tests := map[DigitMode]map[int32]string{
		Dec6: {
			0:        "000000",
			1:        "000001",
			123456:   "123456",
			12345678: "",
		},
		Dec8: {
			0:        "00000000",
			1:        "00000001",
			123456:   "00123456",
			12345678: "12345678",
		},
	}
	for mode, tests := range all_tests {
		for i, s := range tests {
			res := mode.formatOutput(i)
			if res != s {
				t.Errorf("Format Output for DigitMode %d failed. got %s but expected %s", mode, res, s)
			}
		}
	}

}
