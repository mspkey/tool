package msp

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

//Encrypt 加解密
type Encrypt struct {
	PublicKey  string
	PrivateKey string
}

//Rc4DecodeString 用rc4进行解密
func (*Encrypt) Rc4DecodeString(key string, Base64Data string) ([]byte, error) {
	decodeText, err := base64.StdEncoding.DecodeString(Base64Data)
	if err != nil {
		return nil, errors.New("base64 解码失败")
	}
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(decodeText))
	cipher.XORKeyStream(output, decodeText)
	return output, nil
}

//Rc4EncryptByte 用rc4进行加密或解密
func (*Encrypt) Rc4EncryptByte(key string, strData []byte) []byte {
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil
	}
	data := make([]byte, len(strData))
	cipher.XORKeyStream(data, strData)
	return data
}

//Rc4EncryptString 用rc4进行加密 返回base64 格式数据
func (*Encrypt) Rc4EncryptString(key, strData string) string {
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return ""
	}
	data := make([]byte, len(strData))
	cipher.XORKeyStream(data, []byte(strData))
	encoded := base64.StdEncoding.EncodeToString(data)
	return encoded
}

//Md5Encrypt 用MD5进行加密
func (*Encrypt) Md5Encrypt(str string) string {
	if str == "" {
		return ""
	}
	data := []byte(str)
	has := md5.Sum(data)
	md5str1 := fmt.Sprintf("%x", has) //将[]byte转成16进制
	return md5str1
}

// RSACreatKey 用RSA 生成密钥对
//bits 尽量长
func (c *Encrypt) RSACreatKey(bits int) error {

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	//生成私钥
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derStream,
	}
	pr := pem.EncodeToMemory(block)
	c.PrivateKey = string(pr)

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pu := pem.EncodeToMemory(block)
	c.PublicKey = string(pu)
	return nil
}

//RSAEncrypt RSA加密
// Data 要加密的数据
// PuKey 公钥匙
func (c *Encrypt) RSAEncrypt(Data []byte, PuKey string) ([]byte, error) {
	//pem解码
	block, _ := pem.Decode([]byte(PuKey))
	if block == nil {
		return nil, errors.New("public key error")
	}
	//x509解码
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	//类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	//对明文进行加密
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, Data)

}

//RSADecrypt RSA解密
// Data 需要解密的byte数据
// PiKey 私钥
func (c *Encrypt) RSADecrypt(Data []byte, PiKey string) ([]byte, error) {

	//pem解码
	block, _ := pem.Decode([]byte(PiKey))
	//X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	//对密文进行解密
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, Data)
	//返回明文
	return plainText, nil
}

//EncryptAES AES加密
func (c *Encrypt) EncryptAES(key string, plaintext []byte) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	cipher.Encrypt(out, plaintext)
	return out, nil
}

func (c *Encrypt) DecryptAES(key string, encryptText []byte) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(encryptText))
	cipher.Decrypt(out, encryptText)

	return out, nil
}
