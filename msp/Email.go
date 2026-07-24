package msp

import (
	"crypto/tls"
	gomail "gopkg.in/mail.v2"
)

type Email struct {
	SmtpHost string //发件服务器 smtp.163.com
	Point    int    //端口 465
	PwdCode  string //密码或授权码
	Form     string //发送地址
	To       string //接受地址
	Subject  string //主题
	Text     string //内容
}

// Send 发送
func (c *Email) Send() error {
	m := gomail.NewMessage()
	m.SetHeader("From", c.Form)
	m.SetHeader("To", c.To)
	m.SetHeader("Subject", c.Subject)
	m.SetBody("text/plain", c.Text)
	d := gomail.NewDialer(c.SmtpHost, c.Point, c.Form, c.PwdCode)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	err := d.DialAndSend(m)
	if err != nil {
		return err
	}
	return nil
}
