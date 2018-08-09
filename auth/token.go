package auth

import (
	"errors"
	"net/http"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

func verifyToken(client *http.Client, token string) (jws.JWS, error) {
	jt, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return nil, err
	}

	js, ok := jt.(jws.JWS)
	if !ok {
		return nil, errors.New("failed to parse token")
	}

	h := js.Protected()
	kid, ok := h["kid"].(string)
	if !ok {
		return nil, errors.New("invalid header format")
	}

	keys, err := publicKeys(client)
	if err != nil {
		return nil, err
	}
	verified := false
	for _, k := range keys {
		if js.Verify(k.Key, crypto.SigningMethodRS256) == nil {
			verified = true
			break
		}
	}

	if !verified {
		return nil, errors.New("failed to verify token signature. kid = " + kid)
	}
	return js, nil
}
