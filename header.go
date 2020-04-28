package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Header represents a JWT header object.
type Header struct {
	values map[string]interface{}
}

// NewHeader creates a new JWT Header.
func NewHeader() *Header {
	return &Header{values: make(map[string]interface{}, 0)}
}

// Has returns true if the Header has value given by name.
func (header *Header) Has(name string) bool {
	_, exists := header.values[name]
	return exists
}

// Del deletes a value in the Header.
func (header *Header) Del(name string) {
	delete(header.values, name)
}

// Set sets a value in the Header with the given name.
func (header *Header) Set(name string, value interface{}) {
	//JSON RFC: https://tools.ietf.org/html/rfc7159.html#section-6
	//HACK: JSON numbers are double or float64 in Go
	//We will convert any integer to float64 on a set because:
	//1) Values can be recalled after Set with a GetFloat64
	//2) Values will be unmarshalled to float64 by the json package
	//We will do the same with time and []byte
	switch v := value.(type) {
	case []byte:
		header.values[name] = base64.StdEncoding.EncodeToString(v)
	case time.Time:
		header.values[name] = v.Format(time.RFC3339)
	case int16:
		header.values[name] = float64(v)
	case uint16:
		header.values[name] = float64(v)
	case int:
		header.values[name] = float64(v)
	case int32:
		header.values[name] = float64(v)
	case uint32:
		header.values[name] = float64(v)
	case int64:
		header.values[name] = float64(v)
	case uint64:
		header.values[name] = float64(v)
	default:
		header.values[name] = value
	}
}

// Get gets the value in the Header given by name.
func (header *Header) Get(name string) (interface{}, bool) {
	value, exists := header.values[name]
	return value, exists
}

//GetString Gets the string value in the Header given by name.
func (header *Header) GetString(name string) (string, error) {
	errMsg := "jwt: Header.GetString: %v"
	value, exists := header.values[name]
	if !exists {
		return "", fmt.Errorf(errMsg, "No such value "+name)
	}
	str, validType := value.(string)
	if !validType {
		return "", fmt.Errorf(errMsg, name+" is not a string value")
	}
	return str, nil
}

//GetBool Gets the bool value in the Header given by name.
func (header *Header) GetBool(name string) (bool, error) {
	errMsg := "jwt: Header.GetBool: %v"
	value, exists := header.values[name]
	if !exists {
		return false, fmt.Errorf(errMsg, "No such value "+name)
	}
	boolVal, validType := value.(bool)
	if !validType {
		return false, fmt.Errorf(errMsg, name+" is not a bool value")
	}
	return boolVal, nil
}

//GetBytes Gets a byte slice value in the Header given by name.
func (header *Header) GetBytes(name string) ([]byte, error) {
	errMsg := "jwt: Header.GetBytes: %v"
	value, exists := header.values[name]
	if !exists {
		return nil, fmt.Errorf(errMsg, "No such value "+name)
	}
	str, validType := value.(string)
	if !validType {
		return nil, fmt.Errorf(errMsg, name+" is not a string value")
	}
	slice, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf(errMsg, err)
	}
	return slice, nil
}

//GetFloat64 Gets a float64 value in the Header given by name.
func (header *Header) GetFloat64(name string) (float64, error) {
	errMsg := "jwt: Header.GetFloat64: %v"
	value, exists := header.values[name]
	if !exists {
		return 0, fmt.Errorf(errMsg, "No such value "+name)
	}
	float64Val, validType := value.(float64)
	if !validType {
		return 0, fmt.Errorf(errMsg, name+" is not a float64 value")
	}
	return float64Val, nil
}

//GetTime Gets a time value in the Header given by name.
func (header *Header) GetTime(name string) (time.Time, error) {
	errMsg := "jwt: Header.GetTime: %v"
	value, exists := header.values[name]
	if !exists {
		return time.Time{}, fmt.Errorf(errMsg, "No such value "+name)
	}
	str, validType := value.(string)
	if !validType {
		return time.Time{}, fmt.Errorf(errMsg, name+" is not a string value")
	}
	timeVal, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return time.Time{}, fmt.Errorf(errMsg, err)
	}
	return timeVal, nil
}

// Keys gets the names of all the values in the Header.
func (header *Header) Keys() []string {
	keys := make([]string, 0, len(header.values))
	for key := range header.values {
		keys = append(keys, key)
	}
	return keys
}

// Len returns the number of values in the Header.
func (header *Header) Len() int {
	return len(header.values)
}

// Marshal encodes the Header values into JSON.
func (header *Header) Marshal() ([]byte, error) {
	errMsg := "jwt: Header.Marshal: %v"

	t, err := header.GetString("typ")
	if err != nil {
		return nil, fmt.Errorf(errMsg, err)
	}
	if t != "jwt" {
		return nil, fmt.Errorf(errMsg, "Invalid typ "+t)
	}
	a, err := header.GetString("alg")
	if err != nil {
		return nil, fmt.Errorf(errMsg, err)
	}
	if a != "HS256" {
		return nil, fmt.Errorf(errMsg, "Invalid alg "+a)
	}
	bytes, err := json.Marshal(header.values)
	if err != nil {
		return nil, fmt.Errorf(errMsg, err)
	}

	return bytes, err
}

// Unmarshal decodes the header values into a Header object.
func (header *Header) Unmarshal(bytes []byte) error {
	errMsg := "jwt: Header.Marshal: %v"
	err := json.Unmarshal(bytes, &header.values)
	if err != nil {
		return fmt.Errorf(errMsg, err)
	}
	return nil
}
