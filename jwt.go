package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// JWT Represents a JSON Web Token. A JWT contain a Header and Claims.
type JWT struct {
	Header *Header
	Claims *Claims
}

// NewJWT Creates a new JWT. The token contains the typ and alg header.
// The only supported algorithm is HS256 or HMAC SHA256.
func NewJWT() *JWT {
	token := &JWT{Header: NewHeader(), Claims: NewClaims()}
	token.Header.Set("typ", "jwt")
	token.Header.Set("alg", "HS256")
	token.Claims.SetIssuedAt(time.Now())
	return token
}

// Sign Signs and and returns a compacted base 64 encode JWT in the form
// of "header.payload.signature". The secret parameter is the symmetric
// key used to create the signature.
func (jwt *JWT) Sign(secret string) (string, error) {
	errMsg := "jwt: JWT.Sign: %v"
	headerJSON, headerErr := jwt.Header.Marshal()
	if headerErr != nil {
		return "", fmt.Errorf(errMsg, headerErr)
	}
	claimsJSON, claimsErr := jwt.Claims.Marshal()
	if claimsErr != nil {
		return "", fmt.Errorf(errMsg, claimsErr)
	}

	headerBase64 := base64.StdEncoding.EncodeToString(headerJSON)
	claimsBase64 := base64.StdEncoding.EncodeToString(claimsJSON)
	serializedJWT := headerBase64 + "." + claimsBase64

	key := []byte(secret)
	hs256 := hmac.New(sha256.New, key)
	hs256.Write([]byte(serializedJWT))

	value := serializedJWT + "." + base64.StdEncoding.EncodeToString(hs256.Sum(nil))

	return value, nil
}

// Verify Deserializes a compacted JWT and verifies the token using symmetric
// key secret.
func (jwt *JWT) Verify(compact string, secret string) error {
	errMsg := "jwt: JWT.Verify: %v"
	tokens := strings.Split(compact, ".")
	if len(tokens) != 3 {
		return fmt.Errorf(errMsg, "Invalid JWT")
	}
	decodedSig, decodedSigErr := base64.StdEncoding.DecodeString(string(tokens[2]))
	if decodedSigErr != nil {
		return fmt.Errorf(errMsg, "Invalid signature")
	}

	headerJSON, decodeHeaderErr := base64.StdEncoding.DecodeString(string(tokens[0]))
	if decodeHeaderErr != nil {
		return fmt.Errorf(errMsg, "Invalid header")
	}

	claimsJSON, decodeClaimsErr := base64.StdEncoding.DecodeString(string(tokens[1]))
	if decodeClaimsErr != nil {
		return fmt.Errorf(errMsg, "Invalid claims")
	}

	unmarshalHeaderErr := jwt.Header.Unmarshal(headerJSON)
	if unmarshalHeaderErr != nil {
		return fmt.Errorf(errMsg, unmarshalHeaderErr)
	}

	unmarshalClaimsErr := jwt.Claims.Unmarshal(claimsJSON)
	if unmarshalClaimsErr != nil {
		return fmt.Errorf(errMsg, unmarshalClaimsErr)
	}

	message := tokens[0] + "." + tokens[1]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(decodedSig, expectedMAC) {
		return fmt.Errorf(errMsg, "Invalid signature")
	}

	return nil
}
