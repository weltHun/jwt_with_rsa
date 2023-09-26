package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"time"
)

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func createPKI(ctx context.Context) error {
	var privateKey *rsa.PrivateKey
	var p *rsa.PublicKey
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	p = &privateKey.PublicKey

	pubASN1, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return err
	}

	priv, err := json.Marshal(privateKey)
	if err != nil {
		return err
	}
	_, err = db.RPush(ctx, "privateKey", priv).Result()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(pubASN1)
	kid := hex.EncodeToString(hash[:])

	nByte := p.N.Bytes()

	eBytes := big.NewInt(int64(p.E)).Bytes()

	n := base64.URLEncoding.EncodeToString(nByte)
	e := base64.URLEncoding.EncodeToString(eBytes)
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   n,
		"use": "sig",
		"e":   e,
		"kid": kid,
	}

	j, err := json.Marshal(jwk)

	_, err = db.RPush(ctx, "jwk", j).Result()
	if err != nil {
		return err
	}
	return nil
}

func createJWT(ctx context.Context) (map[string]interface{}, error) {
	res := make(map[string]interface{})
	priv, err := db.LIndex(ctx, "privateKey", 0).Result()
	jwkData, err := db.LIndex(ctx, "jwk", 0).Result()
	if err != nil {
		return nil, err
	}
	var privateKey *rsa.PrivateKey
	var jwk map[string]interface{}
	if err = json.Unmarshal([]byte(priv), &privateKey); err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(jwkData), &jwk); err != nil {
		return nil, err
	}
	token := jwt.New(jwt.SigningMethodRS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "1234567890"
	claims["name"] = "John Doe"
	claims["iss"] = "iss"
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	token.Header["kid"] = jwk["kid"]

	tokenStr, _ := token.SignedString(privateKey)

	res["jwt"] = tokenStr

	return res, nil
}

func getJWKs(ctx context.Context) (map[string]interface{}, error) {
	length, err := db.LLen(ctx, "jwk").Result()
	if err != nil {
		return nil, err
	}
	jwks, err := db.LRange(ctx, "jwk", 0, length-1).Result()
	if err != nil {
		return nil, err
	}
	res := make(map[string]interface{})
	var ele []map[string]interface{}
	for _, jwk := range jwks {
		var j map[string]interface{}
		if err := json.Unmarshal([]byte(jwk), &j); err != nil {
			return nil, err
		}
		if err != nil {
			return nil, err
		}
		ele = append(ele, map[string]interface{}{
			"kty": j["kty"],
			"n":   j["n"],
			"use": j["use"],
			"e":   j["e"],
			"kid": j["kid"],
		})
	}
	res["keys"] = ele
	return res, nil
}

func validate(ctx context.Context, header string) (map[string]interface{}, error) {
	length, err := db.LLen(ctx, "jwk").Result()
	if err != nil {
		return nil, err
	}
	jwks, err := db.LRange(ctx, "jwk", 0, length-1).Result()
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(header, func(token *jwt.Token) (interface{}, error) {
		for _, jwkString := range jwks {
			jwk := make(map[string]interface{})
			if err := json.Unmarshal([]byte(jwkString), &jwk); err != nil {
				return nil, err
			}
			fmt.Println(token.Header["kid"], jwk["kid"])
			if token.Header["kid"].(string) == jwk["kid"] {
				p, err := ParseRSAPublicKeyFromJWK(jwk)
				if err != nil {
					return nil, err
				}
				return p, nil
			}
		}
		return nil, errors.New("not matching publicKey")
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}
