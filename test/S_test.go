package test

import (
	"fmt"
	"testing"

	"github.com/mspkey/tool/msp"
)

func TestEscad(t *testing.T) {
	//私钥
	//spi:="45435332200000005674EB7F57EF2694B2437A1ED91DD09B1C4E18984C606F8BF39A98F5E9F5674CFB1E9280F7CF8E0D6C71AE136ACF5F4E4B4F18F5B6FCBB27A9912174C188A6EF354E7F806B0439E03347D99C44E994FBCCE0190468D44BD0B16EF7C4065CEA3A"
	// 易语言公钥十六进制
	pubHex := "45435331200000005674EB7F57EF2694B2437A1ED91DD09B1C4E18984C606F8BF39A98F5E9F5674CFB1E9280F7CF8E0D6C71AE136ACF5F4E4B4F18F5B6FCBB27A9912174C188A6EF"
	// 签名base64
	sigB64 := "llQnIoV5fqoZqd/OECT7Nz145weNysm8aMCKP1ndqWUKl2rPFaSCIpJ2XHEhUb513X/tFra9HqWGr6mbNIjM/w=="
	// 原始数据
	data := []byte(`{ExeID:110110}`)

	verify, err := (&msp.Encrypt{}).ECDSAVerify(pubHex, sigB64, data)
	if err != nil {
		t.Error(err)
	}
	t.Log(verify)
}

func TestEscadSign(t *testing.T) {
	//私钥
	priHex := "45435332200000005674EB7F57EF2694B2437A1ED91DD09B1C4E18984C606F8BF39A98F5E9F5674CFB1E9280F7CF8E0D6C71AE136ACF5F4E4B4F18F5B6FCBB27A9912174C188A6EF354E7F806B0439E03347D99C44E994FBCCE0190468D44BD0B16EF7C4065CEA3A"
	// 易语言公钥十六进制
	pubHex := "45435331200000005674EB7F57EF2694B2437A1ED91DD09B1C4E18984C606F8BF39A98F5E9F5674CFB1E9280F7CF8E0D6C71AE136ACF5F4E4B4F18F5B6FCBB27A9912174C188A6EF"
	// 原始数据
	data := []byte(`{ExeID:110110}`)

	// 签名
	sigB64, err := (&msp.Encrypt{}).ECDSASign(priHex, data)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(sigB64)
	// 验签
	verify, err := (&msp.Encrypt{}).ECDSAVerify(pubHex, sigB64, data)
	if err != nil {
		t.Error(err)
	}
	t.Log(verify)
}

func TestEscadCreatKey(t *testing.T) {
	e := &msp.Encrypt{}
	if err := e.ECDSACreatKey(); err != nil {
		t.Error(err)
	}
	fmt.Println("公钥:", e.PublicKey)
	fmt.Println("私钥:", e.PrivateKey)

	// 用生成的密钥对签名验签
	data := []byte(`{ExeID:110110}`)
	sigB64, err := e.ECDSASign(e.PrivateKey, data)
	if err != nil {
		t.Error(err)
	}
	verify, err := e.ECDSAVerify(e.PublicKey, sigB64, data)
	if err != nil {
		t.Error(err)
	}
	t.Log(verify)
}
