package test

import (
	"fmt"
	"github.com/mspkey/tool/msp"
	"github.com/mspkey/tool/sdk"
	"log"
	"testing"
)

func TestAes256CbcEncryptDecrypt(t *testing.T) {
	encrypt := msp.Encrypt{}
	// AES256 密钥：严格32字节
	aes256Key := []byte("646e0cdba20867821d3cc05000000000")
	originText := []byte("测试AES256-CBC跨语言加密内容")
	//646e0cdba20867821d3cc050
	// 加密
	encStr, err := encrypt.Aes256CbcEncrypt(originText, aes256Key)
	if err != nil {
		panic(err)
	}
	fmt.Println("加密Base64：", encStr)

	// 解密
	decByte, err := encrypt.Aes256CbcDecrypt(encStr, aes256Key)
	if err != nil {
		panic(err)
	}
	fmt.Println("解密明文：", string(decByte))
}

func TestSDK(t *testing.T) {
	DevID := sdk.GetDevID()
	cfg := sdk.Config{
		IP:       "127.0.0.1:8820",
		ExeID:    "6a212d15840856755db34daa",
		Version:  "1.0.0",
		DevID:    DevID,
		AdminKey: "6a2108730662702a86ef00ba",
	}
	ms := sdk.MspKey{}
	err := ms.Init(cfg)
	if err != nil {
		log.Fatalln(err)
	}
	err = ms.CarLogin("53e40bd6-64be-4f0c-87e4-b63fdaff1afc")
	if err != nil {
		log.Fatalln(err)
	}

	auth, err := ms.VmpAuth()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("<UNK>", auth)

	//data, err := ms.GetVariable("X70h_401000")
	//if err != nil {
	//	log.Fatalln(err)
	//}
	//log.Println("<UNK>", string(data))

	//err = ms.GetUserInfo()
	//if err != nil {
	//	log.Fatalln(err)
	//}

	//err = ms.Login("test123", "test123")
	//if err != nil {
	//	log.Fatalln(err)
	//}

	//err = ms.QuickLogin()
	//if err != nil {
	//	log.Fatalln(err)
	//}
	//
	//info, err := ms.GetExeInfo()
	//if err != nil {
	//	log.Fatalln(err)
	//}
	//fmt.Println("<UNK>", info)

}
