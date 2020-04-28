package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Claims represents a JWT claims section.
type Claims struct {
	values map[string]interface{}
}

// NewClaims creates a new JWT Claims object.
func NewClaims() *Claims {
	return &Claims{values: make(map[string]interface{}, 0)}
}

// Has returns true if the Claims has value with the given name.
func (claims *Claims) Has(name string) bool {
	_, exists := claims.values[name]
	return exists
}

// SetExpiration sets the expiration timestamp for the Claims.
func (claims *Claims) SetExpiration(exp time.Time) {
	claims.values["exp"] = exp.UnixNano()
}

// GetExpiration gets the expiration timestamp for the Claims.
func (claims *Claims) GetExpiration() (time.Time, error) {
	zeroDate := time.Unix(0, 0)
	errMsg := "jwt: Claims.GetExpiration: %v"

	value, exists := claims.values["exp"]
	if !exists {
		return zeroDate, fmt.Errorf(errMsg, "No such value expt")
	}
	nsecs, validType := value.(int64)
	if !validType {
		return zeroDate, fmt.Errorf(errMsg, "Invalid exp value")
	}
	return time.Unix(0, nsecs), nil
}

// SetNotBefore sets the not before timestamp for the Claims.
func (claims *Claims) SetNotBefore(nbf time.Time) {
	claims.values["nbf"] = nbf.UnixNano()
}

// GetNotBefore gets the not before timestamp for the Claims.
func (claims *Claims) GetNotBefore() (time.Time, error) {
	zeroDate := time.Unix(0, 0)
	errMsg := "jwt: Claims.GetNotBefore: %v"

	value, exists := claims.values["nbf"]
	if !exists {
		return zeroDate, fmt.Errorf(errMsg, "No such value nbf")
	}
	nsecs, validType := value.(int64)
	if !validType {
		return zeroDate, fmt.Errorf(errMsg, "Invalid nbf value")
	}
	return time.Unix(0, nsecs), nil
}

// SetIssuedAt sets the issued at timestamp for the Claims.
func (claims *Claims) SetIssuedAt(iat time.Time) {
	claims.values["iat"] = iat.UnixNano()
}

// GetIssuedAt gets the issued at timestamp for the Claims.
func (claims *Claims) GetIssuedAt() (time.Time, error) {
	zeroDate := time.Unix(0, 0)
	errMsg := "jwt: Claims.GetIssuedAt: %v"

	value, exists := claims.values["iat"]
	if !exists {
		return zeroDate, fmt.Errorf(errMsg, "No such value iat")
	}
	nsecs, validType := value.(int64)
	if !validType {
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
	str, validType := value.(string)
	if !validType {
		return "", fmt.Errorf(errMsg, "Invalid iss value")
	}
	return str, nil
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
	str, validType := value.(string)
	if !validType {
		return "", fmt.Errorf(errMsg, "Invalid aud value")
	}
	return str, nil
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
	str, validType := value.(string)
	if !validType {
		return "", fmt.Errorf(errMsg, "Invalid prn value")
	}
	return str, nil
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
	str, validType := value.(string)
	if !validType {
		return "", fmt.Errorf(errMsg, "Invalid jti value")
	}
	return str, nil
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
	str, validType := value.(string)
	if !validType {
		return "", fmt.Errorf(errMsg, "Invalid typ value")
	}
	return str, nil
}

// Del Deletes value in the Claims.
func (claims *Claims) Del(name string) {
	delete(claims.values, name)
}

// Set sets a value in the Claims
func (claims *Claims) Set(name string, value interface{}) {
	//JSON RFC: https://tools.ietf.org/html/rfc7159.html#section-6
	//HACK: JSON numbers are double or float64 in Go
	//We will convert any integer to float64 on a set because:
	//1) Values can be recalled after Set with a GetFloat64
	//2) Values will be unmarshalled to float64 by the json package
	//We will do the same with time and []byte
	switch v := value.(type) {
	case []byte:
		claims.values[name] = base64.StdEncoding.EncodeToString(v)
	case time.Time:
		claims.values[name] = v.Format(time.RFC3339)
	case int16:
		claims.values[name] = float64(v)
	case uint16:
		claims.values[name] = float64(v)
	case int:
		claims.values[name] = float64(v)
	case int32:
		claims.values[name] = float64(v)
	case uint32:
		claims.values[name] = float64(v)
	case int64:
		claims.values[name] = float64(v)
	case uint64:
		claims.values[name] = float64(v)
	default:
		claims.values[name] = value
	}
}

// Get gets the value in the Header given by name.
func (claims *Claims) Get(name string) (interface{}, bool) {
	value, exists := claims.values[name]
	return value, exists
}

//GetString Gets the string value in the Claims given by name.
func (claims *Claims) GetString(name string) (string, error) {
	errMsg := "jwt: Claims.GetString: %v"
	value, exists := claims.values[name]
	if !exists {
		return "", fmt.Errorf(errMsg, "No such value "+name)
	}
	str, validType := value.(string)
	if !validType {
		return "", fmt.Errorf(errMsg, name+" is not a string value")
	}
	return str, nil
}

//GetBool Gets the bool value in the Claims given by name.
func (claims *Claims) GetBool(name string) (bool, error) {
	errMsg := "jwt: Claims.GetBool: %v"
	value, exists := claims.values[name]
	if !exists {
		return false, fmt.Errorf(errMsg, "No such value "+name)
	}
	boolVal, validType := value.(bool)
	if !validType {
		return false, fmt.Errorf(errMsg, name+" is not a bool value")
	}
	return boolVal, nil
}

//GetBytes Gets a byte slice value in the Claims given by name.
func (claims *Claims) GetBytes(name string) ([]byte, error) {
	errMsg := "jwt: Claims.GetBytes: %v"
	value, exists := claims.values[name]
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

//GetFloat64 Gets a float64 value in the Claims given by name.
func (claims *Claims) GetFloat64(name string) (float64, error) {
	errMsg := "jwt: Claims.GetFloat64: %v"
	value, exists := claims.values[name]
	if !exists {
		return 0, fmt.Errorf(errMsg, "No such value "+name)
	}
	float64Val, validType := value.(float64)
	if !validType {
		return 0, fmt.Errorf(errMsg, name+" is not a float64 value")
	}
	return float64Val, nil
}

//GetTime Gets a time value in the Claims given by name.
func (claims *Claims) GetTime(name string) (time.Time, error) {
	errMsg := "jwt: Claims.GetTime: %v"
	value, exists := claims.values[name]
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

// Keys gets the names of all the values in the Claims.
func (claims *Claims) Keys() []string {
	keys := make([]string, 0, len(claims.values))
	for key := range claims.values {
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
