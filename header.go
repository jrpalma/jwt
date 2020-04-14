package jwt

import (
	"encoding/json"
	"fmt"
)

// Header represents a JWT header object.
type Header struct {
	values map[string]string
}

// NewHeader creates a new JWT Header.
func NewHeader() *Header {
	return &Header{values: make(map[string]string, 0)}
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
func (header *Header) Set(name string, value string) {
	header.values[name] = value
}

// Get gets the value in the Header given by name.
func (header *Header) Get(name string) string {
	value, exists := header.values[name]
	if exists {
		return value
	}
	return ""
}

// Keys gets the names of all the values in the Header.
func (header *Header) Keys() []string {
	keys := make([]string, 0, len(header.values))
	for _, key := range header.values {
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

	if !header.Has("typ") {
		return nil, fmt.Errorf(errMsg, "Missing header typ")
	}
	if header.Get("typ") != "jwt" {
		return nil, fmt.Errorf(errMsg, "Missing header jwt")
	}
	if !header.Has("alg") {
		return nil, fmt.Errorf(errMsg, "Missing header alg")
	}
	if header.Get("alg") != "HS256" {
		return nil, fmt.Errorf(errMsg, "Invalid alg header")
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
