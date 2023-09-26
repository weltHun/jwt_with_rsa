package main

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

func ParseRSAPublicKeyFromJWK(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nBytes, err := base64.URLEncoding.DecodeString(jwk["n"].(string))
	if err != nil {
		return nil, err
	}

	eBytes, err := base64.URLEncoding.DecodeString(jwk["e"].(string))
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes).Int64()

	return &rsa.PublicKey{
		N: n,
		E: int(e),
	}, nil
}
