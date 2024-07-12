package msp

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"strconv"
	"strings"
	"time"
)

// Token 关于token 的方法
type Token struct {
}

//GetToken 生成token  name: 被加密的字符串   key: 加密的密钥  exptime:过期时间时间戳
func (c *Token) GetToken(Data bson.M, Key string, ExpTime int64) string {

	//请求设置
	claims := make(jwt.MapClaims)
	claims["exp"] = ExpTime
	claims["iat"] = time.Now().Unix()
	claims["Data"] = Data

	//新建一个请求  把请求设置写入其中 根据加密方式
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//签名 字符串
	tokenString, _ := token.SignedString([]byte(Key))
	return tokenString
}

//CheckToken 校验token是否有效 token: token  key:解密的密钥
func (c *Token) CheckToken(token, key string) (b bool, t *jwt.Token) {
	t, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return false, nil
	}
	return true, t
}

//IsToken 解析到期时间 key:密钥 返回到期时间和name 如果为0 token错误或过期
func (c *Token) IsToken(token, key string) (bson.M, int, error) {

	ok, u := c.CheckToken(token, key)
	if ok {
		if t, ok := u.Claims.(jwt.MapClaims); ok {

			ExpTime := t["exp"]
			Data := t["Data"]

			marshal, err := json.Marshal(Data)
			if err != nil {
				return nil, 0, err
			}

			var f bson.M
			err = json.Unmarshal(marshal, &f)
			if err != nil {
				return nil, 0, err
			}

			//把接口类型转成字符串
			str := fmt.Sprintf("%f", ExpTime)
			str = strings.Split(str, ".")[0]
			//转换为int64
			num, _ := strconv.Atoi(str)
			if num == 0 {
				return nil, 0, errors.New("token已过期")
			}
			return f, num, nil

		}
	}
	return nil, 0, errors.New("错误的token")
}
