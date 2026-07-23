package test

import (
	"errors"
	"fmt"
	"github.com/mspkey/tool/sdk"
	"log"
	"testing"
)

// Start 验证启动 在你的主程序里调用
func TestPS(t *testing.T) {
	//DevID := sdk.GetDevID()
	cfg := sdk.Config{
		IP:       "v1.msplock.vip:8810",
		ExeID:    "65bc7fe8defb0198aac98e3e",
		Version:  "1.0.0",
		DevID:    "DevID",
		AdminKey: "646e0cdba20867821d3cc050",
	}
	ms := sdk.MspKey{}
	err := ms.Init(cfg)
	if err != nil {
		log.Fatalln(err)
	}

	err = ms.QuickLogin()
	if err != nil {
		log.Fatalln(err)
	}

	if !ms.IsLogin() {
		log.Fatalln(errors.New("尚未登录"))
	}

	err = ms.GetUserInfo()
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(fmt.Sprintf("到期时间为:%s", ms.Info.EndTime))
}
