package msp

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JwtUtil struct {
	secret []byte
}

func NewJwtUtil(secret string) *JwtUtil {
	return &JwtUtil{
		secret: []byte(secret),
	}
}

type CustomClaims struct {
	Data any `json:"data"`
	jwt.RegisteredClaims
}

// GenerateToken 传入任意结构体/map生成token
func (j *JwtUtil) GenerateToken(payload any, expireDuration time.Duration) (string, error) {
	t := time.Now()
	claims := CustomClaims{
		Data: payload,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(t.Add(expireDuration)),
			IssuedAt:  jwt.NewNumericDate(t),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

func (j *JwtUtil) ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrSignatureInvalid
}
