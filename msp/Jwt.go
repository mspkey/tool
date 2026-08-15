package msp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	Data string `json:"Data"`
	jwt.RegisteredClaims
}

// GenerateToken 传入任意结构体/map生成token
func (j *JwtUtil) GenerateToken(payload any, expireDuration time.Duration) (string, error) {

	marshal, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	toString := base64.StdEncoding.EncodeToString(marshal)
	claims := CustomClaims{
		Data: toString,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expireDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

// ParseToken token解析 target 结构体指针
func (j *JwtUtil) ParseToken(tokenStr string, target any) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("不支持的签名算法")
		}
		return j.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token解析失败: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("token无效或过期")
	}

	decodeString, err := base64.StdEncoding.DecodeString(claims.Data)
	if err != nil {
		return nil, errors.New("base64 解析失败")
	}

	err = json.Unmarshal(decodeString, &target)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
