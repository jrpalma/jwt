package jwt

import "testing"
import "time"

func TestJWT(test *testing.T) {
	token := NewJWT()

	t, err := token.Header.GetString("typ")
	if err != nil {
		test.Error(err.Error())
	}
	if t != "jwt" {
		test.Errorf("Expected jwt for typ, but got %v instead", t)
	}
	a, err := token.Header.GetString("alg")
	if err != nil {
		test.Error(err.Error())
	}
	if a != "HS256" {
		test.Errorf("Expected jwt for typ, but got %v instead", a)
	}

	now := time.Now()
	f := float64(3.14)
	i16 := int16(-1)
	ui16 := uint16(1)
	i32 := int32(-1)
	ui32 := uint32(1)
	i64 := int64(-1)
	ui64 := uint64(1)
	i := int(-1)
	str := "str"
	b := false

	token.Claims.Set("user", "jrpalma")
	token.Claims.Set("admin", "true")
	token.Claims.Set("city", "Houston")
	token.Claims.SetExpiration(time.Now())
	token.Claims.Set("now", now)
	token.Claims.Set("float64", f)
	token.Claims.Set("int", i)
	token.Claims.Set("str", str)
	token.Claims.Set("bool", b)
	token.Claims.Set("int16", i16)
	token.Claims.Set("uint16", ui16)
	token.Claims.Set("int32", i32)
	token.Claims.Set("uint32", ui32)
	token.Claims.Set("int64", i64)
	token.Claims.Set("uint64", ui64)
	token.Claims.Set("bytes", []byte{1, 2, 3})

	compact, signErr := token.Sign("secret")
	if signErr != nil {
		test.Errorf("Failed to sign token: %v", signErr)
	}

	verifyErr := token.Verify(compact, "secret")
	if verifyErr != nil {
		test.Errorf("Failed to verify token: %v", verifyErr)
	}
	verifyErr = token.Verify(compact, "invalid_secret")
	if verifyErr == nil {
		test.Errorf("Failed to verify token: %v", verifyErr)
	}

	token.Header.Set("typ", "invalid")
	_, signErr = token.Sign("secret")
	if signErr == nil {
		test.Errorf("Failed to sign token: %v", signErr)
	}

	verifyErr = token.Verify("invalid", "secret")
	if verifyErr == nil {
		test.Error("Verify should have failed with invalid base64")
	}
	verifyErr = token.Verify("#.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.#", "secret")
	if verifyErr == nil {
		test.Error("Verify should have failed with invalid base64")
	}
	verifyErr = token.Verify("#.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "secret")
	if verifyErr == nil {
		test.Error("Verify should have failed with invalid base64")
	}
	verifyErr = token.Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "secret")
	if verifyErr == nil {
		test.Error("Verify should have failed with invalid base64")
	}
	verifyErr = token.Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.#.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "secret")
	if verifyErr == nil {
		test.Error("Verify should have failed with invalid base64")
	}
	verifyErr = token.Verify("ew0KICAiYWxnIjogIkhTMjU2IiwNCiAgInR5cCI6ICJKV1QiDQo=.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "secret")
	if verifyErr == nil {
		test.Error("Verify should have failed with invalid base64")
	}
	verifyErr = token.Verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ew0KICAic3ViIjogIjEyMzQ1Njc4OTAiLA0KICAibmFtZSI6ICJKb2huIERvZSIsDQogICJhZG1pbiI6IHRydWUNCg==.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "secret")
	if verifyErr == nil {
		test.Error("Verify should have failed with invalid base64")
	}
}
