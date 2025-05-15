package test

import (
	"errors"
	"fmt"
	"github.com/mspkey/tool/sdk"
	"log"
	"testing"
	"time"
)

func TestAdd(t *testing.T) {
	// 测试代码

	// Start 验证启动 在你的主程序里调用
	DevID := sdk.GetDevID()
	cfg := sdk.Config{
		IP:       "127.0.0.1:8810",
		ExeID:    "67f8bf6a2203dc94ccbab1fd",
		Version:  "1.0.0",
		DevID:    DevID,
		AdminKey: "67f8bf3e2203dc94ccbab1fb",
	}
	ms := sdk.MspKey{}
	ms.IsDug = true
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
	fmt.Println(fmt.Sprintf("到期时间为:%s", ms.Info.EndTime))

	for true {
		time.Sleep(time.Second * 3)
		log.Println("-->")
	}

}
