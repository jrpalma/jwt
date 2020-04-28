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
	str, err := claims.GetString("iss")
	if err != nil {
		test.Error(err.Error())
	}
	if str != "jwt" {
		test.Errorf("Expected iss to be jwt, but got %v instead", str)
	}
	str, err = claims.GetString("sub")
	if err != nil {
		test.Error(err.Error())
	}
	if str != "TestToken" {
		test.Errorf("Expected sub to be TestToken, but got %v instead", str)
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

func TestReservedTimeClaims(test *testing.T) {
	claims := NewClaims()
	now := time.Now()
	claims.SetIssuedAt(now)
	claims.SetExpiration(now)
	claims.SetNotBefore(now)
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

}
func TestReservedClaims1(test *testing.T) {
	claims := NewClaims()
	claims.SetAudience("USA")
	claims.SetIssuer("iss")
	claims.SetJTI("jti")
	claims.SetPrincipal("prn")
	claims.SetType("typ")

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

}
func TestReservedClaims2(test *testing.T) {
	claims := NewClaims()
	claims.SetAudience("USA")
	claims.SetIssuer("iss")
	claims.SetJTI("jti")
	claims.SetPrincipal("prn")
	claims.SetType("typ")

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
	_, err := claims.GetString("bogus")
	if err == nil {
		test.Error("Get should have failed with invalid field.")
	}

	if err := claims.Unmarshal([]byte("invalid JSON")); err == nil {
		test.Error("Unmarshal should have failed with invalid JSON.")
	}
}
func TestClaimTypes(test *testing.T) {
	claims := NewClaims()
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

	claims.Set("now", now)
	claims.Set("float64", f)
	claims.Set("int", i)
	claims.Set("str", str)
	claims.Set("bool", b)
	claims.Set("int16", i16)
	claims.Set("uint16", ui16)
	claims.Set("int32", i32)
	claims.Set("uint32", ui32)
	claims.Set("int64", i64)
	claims.Set("uint64", ui64)
	claims.Set("bytes", []byte{1, 2, 3})

	if _, err := claims.GetTime("now"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("float64"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("int"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetString("str"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetBool("bool"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("int16"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("uint16"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("int32"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("uint32"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("int64"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetFloat64("uint64"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := claims.GetBytes("bytes"); err != nil {
		test.Errorf(err.Error())
	}

}
func TestNonExistingClaims1(test *testing.T) {
	claims := NewClaims()

	if _, ok := claims.Get("unknown"); ok {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetTime("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetString("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetBool("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetBytes("unknown"); err == nil {
		test.Errorf("Should fail")
	}

}
func TestNonExistingClaims2(test *testing.T) {
	claims := NewClaims()
	claims.Set("unknown", nil)

	if _, ok := claims.Get("unknown"); !ok {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetTime("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetString("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetBool("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := claims.GetBytes("unknown"); err == nil {
		test.Errorf("Should fail")
	}
}
