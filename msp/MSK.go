package msp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"time"
)

const TimeInit = "2006-01-02 15:04:05"

// Mspkey 解析数据
func Mspkey(Data, Key string, out interface{}) error {

	sDec, err := base64.StdEncoding.DecodeString(Data)
	if err != nil {
		return errors.New("base64解码失败")
	}

	var p Encrypt
	str := p.Rc4EncryptByte(Key, sDec)
	err = json.Unmarshal(str, &out)
	if err != nil {
		return err
	}

	return nil

}

// GetRandomString 获取随机字母  l:长度
func GetRandomString(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

// TimeFormat 格式化时间
func TimeFormat(time time.Time) string {
	str := time.Local().Format(TimeInit)

	return str
}
