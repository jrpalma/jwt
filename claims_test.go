package jwt

import (
	"testing"
	"time"
)

func TestClaims(test *testing.T) {
	claims := NewClaims()
	if claims.Len() != 0 {
		test.Errorf("Expected claims len to be 0, but got %v instead", claims.Len())
	}
	claims.Set("iss", "jwt")
	if claims.Len() != 1 {
		test.Errorf("Expected claims len to be 1, but got %v instead", claims.Len())
	}
	if !claims.Has("iss") {
		test.Error("Expected to have value iss, but it does not")
	}
	claims.Set("sub", "TestToken")
	if claims.Len() != 2 {
		test.Errorf("Expected claims len to be 2, but got %v instead", claims.Len())
	}
	if !claims.Has("sub") {
		test.Error("Expected to have value sub, but it does not")
	}
	if claims.Get("iss") != "jwt" {
		test.Errorf("Expected iss to be jwt, but got %v instead", claims.Get("iss"))
	}
	if claims.Get("sub") != "TestToken" {
		test.Errorf("Expected sub to be TestToken, but got %v instead", claims.Get("iss"))
	}
	keys := claims.Keys()
	if len(keys) != 2 {
		test.Errorf("Expected the number of keys to be 2, but got %v instead", len(keys))
	}
	jsonBytes, err := claims.Marshal()
	if err != nil {
		test.Errorf("Unable to marshal claims to JSON: %v", err)
	}
	claims2 := NewClaims()
	err = claims2.Unmarshal(jsonBytes)
	if err != nil {
		test.Logf("Unable to decode JSON claims: %v", string(jsonBytes))
	}

	claims.Del("iss")
	claims.Del("sub")
	if claims.Has("iss") {
		test.Error("Expected iss to be removed, but the claims has the value")
	}
	if claims.Has("sub") {
		test.Error("Expected sub to be removed, but the claims has the value")
	}
	keys = claims.Keys()
	if len(keys) != 0 {
		test.Errorf("Expected the number of keys to be 0, but got %v instead", len(keys))
	}

}

func TestReservedClaims(test *testing.T) {
	claims := NewClaims()
	now := time.Now()
	claims.SetIssuedAt(now)
	claims.SetExpiration(now)
	claims.SetNotBefore(now)
	claims.SetAudience("USA")
	claims.SetIssuer("iss")
	claims.SetJTI("jti")
	claims.SetPrincipal("prn")
	claims.SetType("typ")

	if t, err := claims.GetIssuedAt(); err != nil {
		test.Error(err.Error())
	} else if !t.Equal(now) {
		test.Errorf("Expected %v, but got %v instead", now, t)
	}

	if t, err := claims.GetExpiration(); err != nil {
		test.Error(err.Error())
	} else if !t.Equal(now) {
		test.Errorf("Expected %v, but got %v instead", now, t)
	}

	if t, err := claims.GetNotBefore(); err != nil {
		test.Error(err.Error())
	} else if !t.Equal(now) {
		test.Errorf("Expected %v, but got %v instead", now, t)
	}

	if v, err := claims.GetAudience(); err != nil {
		test.Error(err.Error())
	} else if v != "USA" {
		test.Errorf("Expected aud to be USA, but got %v instead", v)
	}

	if v, err := claims.GetIssuer(); err != nil {
		test.Error(err.Error())
	} else if v != "iss" {
		test.Errorf("Expected iss to be iss, but got %v instead", v)
	}

	if v, err := claims.GetJTI(); err != nil {
		test.Error(err.Error())
	} else if v != "jti" {
		test.Errorf("Expected jti to be jti, but got %v instead", v)
	}

	if v, err := claims.GetPrincipal(); err != nil {
		test.Error(err.Error())
	} else if v != "prn" {
		test.Errorf("Expected prn to be prn, but got %v instead", v)
	}

	if v, err := claims.GetType(); err != nil {
		test.Error(err.Error())
	} else if v != "typ" {
		test.Errorf("Expected typ to be typ, but got %v instead", v)
	}

	claims.Set("exp", "invalid date")
	if _, err := claims.GetExpiration(); err == nil {
		test.Error("GetExpiration should have failed with invalid date.")
	}
	claims.Del("exp")
	if _, err := claims.GetExpiration(); err == nil {
		test.Error("GetExpiration should have failed with missing exp field.")
	}

	claims.Set("nbf", "invalid date")
	if _, err := claims.GetNotBefore(); err == nil {
		test.Error("GeNotBefore should have failed with invalid date.")
	}
	claims.Del("nbf")
	if _, err := claims.GetNotBefore(); err == nil {
		test.Error("GetNotBefore should have failed with missing nbf field.")
	}

	claims.Set("iat", "invalid date")
	if _, err := claims.GetIssuedAt(); err == nil {
		test.Error("GeIssuedAt should have failed with invalid date.")
	}
	claims.Del("iat")
	if _, err := claims.GetIssuedAt(); err == nil {
		test.Error("GetIssuedAt should have failed with missing iat field.")
	}
	claims.Del("iss")
	if _, err := claims.GetIssuer(); err == nil {
		test.Error("GetIssuer should have failed with missing iss field.")
	}
	claims.Del("aud")
	if _, err := claims.GetAudience(); err == nil {
		test.Error("GetAudience should have failed with missing aud field.")
	}
	claims.Del("prn")
	if _, err := claims.GetPrincipal(); err == nil {
		test.Error("GetPrincipal should have failed with missing prn field.")
	}
	claims.Del("jti")
	if _, err := claims.GetJTI(); err == nil {
		test.Error("GetJTI should have failed with missing jti field.")
	}
	claims.Del("typ")
	if _, err := claims.GetType(); err == nil {
		test.Error("GetType should have failed with missing typ field.")
	}
	if v := claims.Get("bogus"); v != "" {
		test.Error("Get should have failed with invalid field.")
	}

	if err := claims.Unmarshal([]byte("invalid JSON")); err == nil {
		test.Error("Unmarshal should have failed with invalid JSON.")
	}
}
