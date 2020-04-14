package jwt

import "testing"

func TestJWT(test *testing.T) {
	token := NewJWT()

	typ := token.Header.Get("typ")
	if typ != "jwt" {
		test.Errorf("Expected jwt for typ, but got %v instead", typ)
	}
	alg := token.Header.Get("alg")
	if alg != "HS256" {
		test.Errorf("Expected HS256 for alg, but got %v instead", alg)
	}

	token.Claims.Set("user", "jrpalma")
	token.Claims.Set("admin", "true")
	token.Claims.Set("city", "Houston")

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
