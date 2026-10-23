package test

import (	
	"log"
	"testing"
	"github.com/mspkey/tool/sdk"
)

// Start 验证启动 在你的主程序里调用
func Start() {
	DevID := sdk.GetDevID()
	cfg := sdk.Config{
		IP:       sdk.LockHost,
		ExeID:    "65bc7fe8defb0198aac98e3e",
		Version:  "1.0.0",
		DevID:    DevID,
		AdminID: "646e0cdba20867821d3cc050",
	}
	ms := sdk.MspkeyPro{}
	err := ms.Init(cfg)
	if err != nil {
		log.Fatalln(err)
	}
	
	err = ms.ScanQrcode()
	if err != nil {
		log.Fatalln(err)
	}

	user, err := ms.GetUserInfo()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("到期时间为:%s", user.EndTime)
}

func TestInit(t *testing.T) {
	Start()
}
