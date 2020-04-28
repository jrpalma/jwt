package jwt

import (
	"testing"
	"time"
)

func TestHeader(test *testing.T) {
	header := NewHeader()
	if header.Len() != 0 {
		test.Errorf("Expected header len to be 0, but got %v instead", header.Len())
	}
	header.Set("typ", "jwt")
	if header.Len() != 1 {
		test.Errorf("Expected header len to be 1, but got %v instead", header.Len())
	}
	header.Set("alg", "HS256")
	if header.Len() != 2 {
		test.Errorf("Expected header len to be 2, but got %v instead", header.Len())
	}
	t, err := header.GetString("typ")
	if err != nil {
		test.Error(err.Error())
	}
	if t != "jwt" {
		test.Errorf("Expected typ to be jwt, but got %v instead", t)
	}
	a, err := header.GetString("alg")
	if err != nil {
		test.Error(err.Error())
	}
	if a != "HS256" {
		test.Errorf("Expected alg to be HS256, but got %v instead", a)
	}
	keys := header.Keys()
	if len(keys) != 2 {
		test.Errorf("Expected the number of keys to be 2, but got %v instead", len(keys))
	}
	jsonBytes, err := header.Marshal()
	if err != nil {
		test.Errorf("Unable to marshal header to JSON: %v", err)
	}
	header2 := NewHeader()
	err = header2.Unmarshal(jsonBytes)
	if err != nil {
		test.Logf("Unable to decode JSON header: %v", string(jsonBytes))
	}

	header.Del("typ")
	if header.Has("typ") {
		test.Error("Expected typ to be removed, but the header has the value")
	}
	_, err = header.Marshal()
	if err == nil {
		test.Errorf("Marshal should fail without typ field: %v", err)
	}
	header.Set("typ", "invalid")
	_, err = header.Marshal()
	if err == nil {
		test.Errorf("Marshal should fail without typ field: %v", err)
	}

}

func TestHeaderFailure(test *testing.T) {
	header := NewHeader()

	if v, ok := header.Get("bogus"); ok || v != nil {
		test.Error("Get should have failed with a bogus header field.")
	}

	if err := header.Unmarshal([]byte("invalid JSON")); err == nil {
		test.Error("Unmarshal should fail with invalid JSON")
	}

	header.Set("typ", "jwt")
	header.Set("alg", "invalid")
	_, err := header.Marshal()
	if err == nil {
		test.Errorf("Marshal should fail with invalid alg field: %v", err)
	}
	header.Del("alg")
	_, err = header.Marshal()
	if err == nil {
		test.Errorf("Marshal should fail without alg field: %v", err)
	}

	header.Del("typ")
	keys := header.Keys()
	if len(keys) != 0 {
		test.Errorf("Expected the number of keys to be 0, but got %v instead", len(keys))
	}
}
func TestHeaderTypes(test *testing.T) {
	header := NewHeader()
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

	header.Set("now", now)
	header.Set("float64", f)
	header.Set("int", i)
	header.Set("str", str)
	header.Set("bool", b)
	header.Set("int16", i16)
	header.Set("uint16", ui16)
	header.Set("int32", i32)
	header.Set("uint32", ui32)
	header.Set("int64", i64)
	header.Set("uint64", ui64)
	header.Set("bytes", []byte{1, 2, 3})

	if _, err := header.GetTime("now"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("float64"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("int"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetString("str"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetBool("bool"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("int16"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("uint16"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("int32"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("uint32"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("int64"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetFloat64("uint64"); err != nil {
		test.Errorf(err.Error())
	}
	if _, err := header.GetBytes("bytes"); err != nil {
		test.Errorf(err.Error())
	}

}
func TestNonExistingHeader1(test *testing.T) {
	header := NewHeader()

	if _, ok := header.Get("unknown"); ok {
		test.Errorf("Should fail")
	}
	if _, err := header.GetTime("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetString("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetBool("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetBytes("unknown"); err == nil {
		test.Errorf("Should fail")
	}

}
func TestNonExistingHeader2(test *testing.T) {
	header := NewHeader()
	header.Set("unknown", nil)

	if _, ok := header.Get("unknown"); !ok {
		test.Errorf("Should fail")
	}
	if _, err := header.GetTime("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetString("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetBool("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetFloat64("unknown"); err == nil {
		test.Errorf("Should fail")
	}
	if _, err := header.GetBytes("unknown"); err == nil {
		test.Errorf("Should fail")
	}
}
