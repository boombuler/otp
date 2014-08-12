package otp_test

import (
	"fmt"
	"github.com/boombuler/barcode/qr"
	"github.com/boombuler/otp"
)

type User string

func (u User) Secret() []byte {
	// Return a user specific secret which must be at least 10 bytes long
	// and should be random and persistent for each account.
	return []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
}

func (u User) Label() string {
	return string(u) // Return a display label for the user account
}

// Initialize TOTP
var totp = otp.NewDefaultTOTP("Test Service")

func ExampleTimeBased() {
	usr := User("Test Account")
	// on "first contact" with the user show a barcode with all needed information to the user:
	uri := totp.OTPAuthUri(usr)
	img, err := qr.Encode(uri, qr.H, qr.Unicode)
	if err != nil {
		// handle error...
	} else {
		_ = img // send img to the user...
	}

	// After that we can check the OTPs from the user:
	userProvidedOTP := "123456"
	if totp.IsValid(account, userProvidedOTP, otp.DefaultTimeTolerance) {
		fmt.Println("Login OK!")
	} else {
		fmt.Println("Failed!")
	}

}
