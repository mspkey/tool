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
		ExeID:    "67f8bf6a2203dc94ccbab1fd",
		Version:  "1.0.0",
		DevID:    DevID,
		AdminKey: "67f8bf3e2203dc94ccbab1fb",
	}

	ms := sdk.MspKey{}
	//ms.IsDug = true
	err := ms.Init(cfg)
	if err != nil {
		log.Fatalln(err)
	}

	//err = ms.CarLogin("7cf12713-ae84-464c-94f3-1eac1cbb9f30")
	//if err != nil {
	//	log.Fatalln(err)
	//}

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

	time.Sleep(1 * time.Hour)

}
