package test

import (
	"errors"
	"fmt"
	"github.com/mspkey/tool/sdk"
	"log"
	"testing"
	"time"
)

func TestOps(t *testing.T) {
	Start()

}

// Start 验证启动 在你的主程序里调用
func Start() {
	DevID := sdk.GetDevID()
	cfg := sdk.Config{
		IP:       "127.0.0.1:8820",
		ExeID:    "697dd630de1185188b262145",
		Version:  "1.0.0",
		DevID:    DevID,
		AdminKey: "697dd606de1185188b262142",
	}

	ms := sdk.MspKey{}
	//ms.IsDug = true
	err := ms.Init(cfg)
	if err != nil {
		log.Fatalln(err)
	}

	err = ms.CarLogin("8d6e5a78-4535-481f-ab75-f793f8685cc3")
	if err != nil {
		log.Fatalln(err)
	}

	//err = ms.QuickLogin()
	//if err != nil {
	//	log.Fatalln(err)
	//}

	if !ms.IsLogin() {
		log.Fatalln(errors.New("尚未登录"))
	}

	err = ms.GetUserInfo()
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(fmt.Sprintf("到期时间为:%s", ms.Info.EndTime))

	time.Sleep(1 * time.Hour)

}
