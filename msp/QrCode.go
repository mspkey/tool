package msp

import (
	"encoding/base64"
	"github.com/skip2/go-qrcode"
	"image/color"
)

//二维码生成

//QrCodeCreateToBase64 二维码生成
func QrCodeCreateToBase64(Content string) (string, error) {
	qr, err := qrcode.New(Content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	qr.BackgroundColor = color.White
	qr.ForegroundColor = color.Black
	png, err := qr.PNG(256)
	if err != nil {
		return "", err
	}
	toString := base64.StdEncoding.EncodeToString(png)
	return toString, err
}
