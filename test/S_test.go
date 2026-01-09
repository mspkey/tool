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

}

// Start 验证启动 在你的主程序里调用
func Start() {
	DevID := sdk.GetDevID()
	cfg := sdk.Config{
		IP:       sdk.LockHost,
		ExeID:    "65bc7fe8defb0198aac98e3e",
		Version:  "1.0.3",
		DevID:    DevID,
		AdminKey: "646e0cdba20867821d3cc050",
	}
	//负载均衡
	balancing, err := sdk.LoadBalancing(cfg.IP)
	if err != nil {
		log.Fatal(err)
	}
	//启动本地UI服务
	go func() {
		sdk.ProxyApi(balancing)
	}()

	time.Sleep(2 * time.Second)

	ms := sdk.MspKey{}
	err = ms.Init(cfg)
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
