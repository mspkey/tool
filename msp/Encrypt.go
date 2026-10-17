package msp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Encrypt 加解密
type Encrypt struct {
	PublicKey  string
	PrivateKey string
}

// Rc4DecodeString 用rc4进行解密
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

// Rc4EncryptByte 用rc4进行加密或解密
func (*Encrypt) Rc4EncryptByte(key string, strData []byte) []byte {
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil
	}
	data := make([]byte, len(strData))
	cipher.XORKeyStream(data, strData)
	return data
}

// Rc4EncryptString 用rc4进行加密 返回base64 格式数据
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

// Md5Encrypt 用MD5进行加密
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
// bits 尽量长
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

// RSAEncrypt RSA加密
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

// RSADecrypt RSA解密
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

// EncryptAES AES加密
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

// PKCS7 填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := make([]byte, padLen)
	for i := range pad {
		pad[i] = byte(padLen)
	}
	return append(data, pad...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("空密文")
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, errors.New("填充长度非法")
	}
	// 校验所有填充字节一致，防攻击
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return nil, errors.New("填充校验失败，密钥错误或数据篡改")
		}
	}
	return data[:len(data)-padLen], nil
}

// Aes256CbcEncrypt AES-256-CBC 加密
// key：必须32字节
// 返回 base64(IV + 密文)
func (c *Encrypt) Aes256CbcEncrypt(plainText, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("AES256密钥必须32字节")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	// 生成16字节随机IV
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	padded := pkcs7Pad(plainText, blockSize)
	cipherBuf := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherBuf, padded)

	// IV拼接密文再base64
	full := append(iv, cipherBuf...)
	return base64.StdEncoding.EncodeToString(full), nil
}

// Aes256CbcDecrypt AES-256-CBC 解密
func (c *Encrypt) Aes256CbcDecrypt(cipherBase64 string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES256密钥必须32字节")
	}
	data, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return nil, errors.New("base64解码失败")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, errors.New("密文过短，缺少IV")
	}

	iv := data[:blockSize]
	cipherText := data[blockSize:]

	decryptMode := cipher.NewCBCDecrypter(block, iv)
	plainPadded := make([]byte, len(cipherText))
	decryptMode.CryptBlocks(plainPadded, cipherText)

	return pkcs7Unpad(plainPadded)
}

// ECDSACreatKey 生成易语言格式的ECDSA(P256)密钥对
// 公钥hex: 4543533120000000("ECS1 ") + X(32) + Y(32)
// 私钥hex: 4543533220000000("ECS2 ") + X(32) + Y(32) + D(32)
func (c *Encrypt) ECDSACreatKey() error {
	priKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	x := priKey.X.Bytes()
	y := priKey.Y.Bytes()
	d := priKey.D.Bytes()

	// 补齐到32字节
	pad := func(b []byte) []byte {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	x, y, d = pad(x), pad(y), pad(d)

	// 公钥: 头部 + X + Y
	pub := append([]byte{0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00}, append(x, y...)...)
	c.PublicKey = strings.ToUpper(hex.EncodeToString(pub))

	// 私钥: 头部 + X + Y + D
	pri := append([]byte{0x45, 0x43, 0x53, 0x32, 0x20, 0x00, 0x00, 0x00}, append(x, append(y, d...)...)...)
	c.PrivateKey = strings.ToUpper(hex.EncodeToString(pri))

	return nil
}

// ECDSASign 用私钥对数据签名
// priHex 易语言私钥hex，8字节头部("ECS2 ")后为 X(32)+Y(32)+D(32)
// 返回 base64(r||s)，r、s 各32字节
func (c *Encrypt) ECDSASign(priHex string, data []byte) (string, error) {
	// 1. 解码私钥hex
	priBytes, err := hex.DecodeString(priHex)
	if err != nil {
		return "", errors.New("私钥hex解码失败")
	}

	// 去掉8字节头部，剩余 X(32)+Y(32)+D(32)
	priRaw := priBytes[8:]
	if len(priRaw) != 96 {
		return "", errors.New("私钥长度不对")
	}

	x := new(big.Int).SetBytes(priRaw[:32])
	y := new(big.Int).SetBytes(priRaw[32:64])
	d := new(big.Int).SetBytes(priRaw[64:])
	priKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}

	// 2. SHA256哈希原文
	hash := sha256.Sum256(data)

	// 3. ECDSA签名
	r, s, err := ecdsa.Sign(rand.Reader, priKey, hash[:])
	if err != nil {
		return "", err
	}

	// 4. r、s各补齐32字节拼接后base64
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ECDSAVerify 验签
func (c *Encrypt) ECDSAVerify(pubHex string, sigB64 string, data []byte) error {
	// 1. 解码公钥hex
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return errors.New("公钥hex解码失败")
	}

	// 👉 重点：易语言这个公钥头部有 "ECS1 " (4543533120 是 ECS1 空格)，是自定义头部！
	// 去掉前面 8 字节头部：4543533120000000，后面才是 P256 的 X,Y 坐标（32+32=64字节）
	pubRaw := pubBytes[8:]
	if len(pubRaw) != 64 {
		return errors.New("公钥XY长度不对")
	}

	x := new(big.Int).SetBytes(pubRaw[:32])
	y := new(big.Int).SetBytes(pubRaw[32:])
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// 2. base64解码签名
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("签名base64解码失败")
	}
	if len(sigBytes) != 64 {
		fmt.Printf("签名长度不是64字节，len=%d\n", len(sigBytes))
		return errors.New("签名长度不是64字节")
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// 3. SHA256哈希原文
	hash := sha256.Sum256(data)

	// 4. ECDSA验签
	ok := ecdsa.Verify(pubKey, hash[:], r, s)
	if ok {
		return nil
	}

	return errors.New("ECDSA验签失败")
}
