package test

import (
	"encoding/json"
	"fmt"
	"github.com/mspkey/tool/bin"
	"github.com/mspkey/tool/msp"
	"github.com/mspkey/tool/sdk"
	"log"
	"testing"
	"time"
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
		ExeID:    "65bc7fe8defb0198aac98e3e",
		Version:  "1.0.0",
		DevID:    DevID,
		AdminKey: "646e0cdba20867821d3cc050",
	}
	ms := sdk.MspKey{}
	err := ms.Init(cfg)
	if err != nil {
		log.Fatalln(err)
	}

	ms.QuickLogin()

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

func TestRunDownUI(t *testing.T) {
	ui := &bin.ClientUI{}
	err := ui.RunDownUI("https://down-tencent.huorong.cn/sysdiag-all-x64-6.0.11.1-2026.07.28.1.exe", "H:\\测试区\\更新测试", "C123.exe")
	if err != nil {
		log.Fatalln(err)
	}
}

func TestToken(t *testing.T) {
	type Osjwt struct {
		Name string    `json:"Name"`
		Pwd  string    `json:"Pwd"`
		Age  int64     `json:"Age"`
		Time time.Time `json:"Time"`
		Is   bool      `json:"Is"`
	}

	p := Osjwt{
		Name: "张三",
		Pwd:  "110110",
		Age:  20,
		Time: time.Now(),
		Is:   true,
	}

	util := msp.NewJwtUtil("test")
	token, err := util.GenerateToken(p, 1*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)

	//解析
	po := msp.NewJwtUtil("test")
	var os Osjwt
	parseToken, err := po.ParseToken(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(parseToken.Data)
	marshal, err := json.Marshal(parseToken.Data)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(marshal, &os)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(os)
}
