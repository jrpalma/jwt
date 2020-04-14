package jwt

import "testing"

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
	if header.Get("typ") != "jwt" {
		test.Errorf("Expected typ to be jwt, but got %v instead", header.Get("typ"))
	}
	if header.Get("alg") != "HS256" {
		test.Errorf("Expected alg to be HS256, but got %v instead", header.Get("typ"))
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

	header.Set("typ", "jwt")
	header.Set("alg", "invalid")
	_, err = header.Marshal()
	if err == nil {
		test.Errorf("Marshal should fail with invalid alg field: %v", err)
	}
	header.Del("alg")
	_, err = header.Marshal()
	if err == nil {
		test.Errorf("Marshal should fail without alg field: %v", err)
	}

	header.Del("typ")
	keys = header.Keys()
	if len(keys) != 0 {
		test.Errorf("Expected the number of keys to be 0, but got %v instead", len(keys))
	}

}

func TestHeaderFailure(test *testing.T) {
	header := NewHeader()
	if val := header.Get("bogus"); val != "" {
		test.Error("Get should have failed with a bogus header field.")
	}

	if err := header.Unmarshal([]byte("invalid JSON")); err == nil {
		test.Error("Unmarshal should fail with invalid JSON")
	}
}
