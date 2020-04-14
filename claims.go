package jwt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Claims represents a JWT claims section.
type Claims struct {
	values map[string]string
}

// NewClaims creates a new JWT Claims object.
func NewClaims() *Claims {
	return &Claims{values: make(map[string]string, 0)}
}

// Has returns true if the Claims has value with the given name.
func (claims *Claims) Has(name string) bool {
	_, exists := claims.values[name]
	return exists
}

// SetExpiration sets the expiration timestamp for the Claims.
func (claims *Claims) SetExpiration(exp time.Time) {
	claims.values["exp"] = fmt.Sprintf("%v", exp.UnixNano())
}

// GetExpiration gets the expiration timestamp for the Claims.
func (claims *Claims) GetExpiration() (time.Time, error) {
	zeroDate := time.Unix(0, 0)
	errMsg := "jwt: Claims.GetExpiration: %v"

	value, exists := claims.values["exp"]
	if !exists {
		return zeroDate, fmt.Errorf(errMsg, "No such value expt")
	}
	nsecs, parseError := strconv.ParseInt(value, 10, 64)
	if parseError != nil {
		return zeroDate, fmt.Errorf(errMsg, "Invalid exp value")
	}
	return time.Unix(0, nsecs), nil
}

// SetNotBefore sets the not before timestamp for the Claims.
func (claims *Claims) SetNotBefore(nbf time.Time) {
	claims.values["nbf"] = fmt.Sprintf("%v", nbf.UnixNano())
}

// GetNotBefore gets the not before timestamp for the Claims.
func (claims *Claims) GetNotBefore() (time.Time, error) {
	zeroDate := time.Unix(0, 0)
	errMsg := "jwt: Claims.GetNotBefore: %v"

	value, exists := claims.values["nbf"]
	if !exists {
		return zeroDate, fmt.Errorf(errMsg, "No such value nbf")
	}
	nsecs, parseError := strconv.ParseInt(value, 10, 64)
	if parseError != nil {
		return zeroDate, fmt.Errorf(errMsg, "Invalid nbf value")
	}
	return time.Unix(0, nsecs), nil
}

// SetIssuedAt sets the issued at timestamp for the Claims.
func (claims *Claims) SetIssuedAt(iat time.Time) {
	claims.values["iat"] = fmt.Sprintf("%v", iat.UnixNano())
}

// GetIssuedAt gets the issued at timestamp for the Claims.
func (claims *Claims) GetIssuedAt() (time.Time, error) {
	zeroDate := time.Unix(0, 0)
	errMsg := "jwt: Claims.GetIssuedAt: %v"

	value, exists := claims.values["iat"]
	if !exists {
		return zeroDate, fmt.Errorf(errMsg, "No such value iat")
	}
	nsecs, parseError := strconv.ParseInt(value, 10, 64)
	if parseError != nil {
		return zeroDate, fmt.Errorf(errMsg, "Invalid iat value")
	}
	return time.Unix(0, nsecs), nil
}

// SetIssuer sets the issuer for the Claims.
func (claims *Claims) SetIssuer(iss string) {
	claims.values["iss"] = iss
}

// GetIssuer gets the issuer for the Claims.
func (claims *Claims) GetIssuer() (string, error) {
	errMsg := "jwt: Claims.GetIssuer: %v"
	value, exists := claims.values["iss"]
	if !exists {
		return "", fmt.Errorf(errMsg, "No such value iss")
	}
	return value, nil
}

// SetAudience sets the audience for the Claims.
func (claims *Claims) SetAudience(aud string) {
	claims.values["aud"] = aud
}

// GetAudience gets the audience for the Claims.
func (claims *Claims) GetAudience() (string, error) {
	errMsg := "jwt: Claims.GetAudience: %v"
	value, exists := claims.values["aud"]
	if !exists {
		return "", fmt.Errorf(errMsg, "No such value aud")
	}
	return value, nil
}

// SetPrincipal sets the principal for the Claims.
func (claims *Claims) SetPrincipal(prn string) {
	claims.values["prn"] = prn
}

// GetPrincipal gets the principal for the Claims.
func (claims *Claims) GetPrincipal() (string, error) {
	errMsg := "jwt: Claims.GetAudience: %v"
	value, exists := claims.values["prn"]
	if !exists {
		return "", fmt.Errorf(errMsg, "No such value prn")
	}
	return value, nil
}

// SetJTI sets the JWT ID for the Claims.
func (claims *Claims) SetJTI(jti string) {
	claims.values["jti"] = jti
}

// GetJTI gets the JWT ID for the Claims.
func (claims *Claims) GetJTI() (string, error) {
	errMsg := "jwt: Claims.GetJTI: %v"
	value, exists := claims.values["jti"]
	if !exists {
		return "", fmt.Errorf(errMsg, "No such value jti")
	}
	return value, nil
}

// SetType sets the type for the Claims.
func (claims *Claims) SetType(typ string) {
	claims.values["typ"] = typ
}

// GetType gets the type for the claim.
func (claims *Claims) GetType() (string, error) {
	errMsg := "jwt: Claims.GetType: %v"
	value, exists := claims.values["typ"]
	if !exists {
		return "", fmt.Errorf(errMsg, "No such value typ")
	}
	return value, nil
}

// Del Deletes value in the Claims.
func (claims *Claims) Del(name string) {
	delete(claims.values, name)
}

// Set sets a value in the Claims
func (claims *Claims) Set(name string, value string) {
	claims.values[name] = value
}

//Get Gets the value in the Claims given by name.
func (claims *Claims) Get(name string) string {
	value, exists := claims.values[name]
	if exists {
		return value
	}
	return ""
}

// Keys gets the names of all the values in the Claims.
func (claims *Claims) Keys() []string {
	keys := make([]string, 0, len(claims.values))
	for _, key := range claims.values {
		keys = append(keys, key)
	}
	return keys
}

// Len returns the number of values in the Claims.
func (claims *Claims) Len() int {
	return len(claims.values)
}

// Marshal encodes the Claims values into JSON.
func (claims *Claims) Marshal() ([]byte, error) {
	errMsg := "jwt: Claims.Marshal: %v"
	//We really do not need to check
	bytes, err := json.Marshal(claims.values)
	if err != nil {
		return nil, fmt.Errorf(errMsg, err)
	}

	return bytes, err
}

// Unmarshal decodes the Claims values into a Claims object.
func (claims *Claims) Unmarshal(bytes []byte) error {
	errMsg := "jwt: Claims.Marshal: %v"
	err := json.Unmarshal(bytes, &claims.values)
	if err != nil {
		return fmt.Errorf(errMsg, err)
	}
	return nil
}
