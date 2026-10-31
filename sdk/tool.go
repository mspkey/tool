package sdk

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/mspkey/tool/msp"
)

// GetDevID 获取设备ID
func GetDevID() string {
	id := msp.DeviceID{}
	address := id.GetMac()
	e := msp.Encrypt{}
	return e.Md5Encrypt(address[0])
}

// pingServer 检测服务器是否可用
// 服务端路由: POST /api/v1/Ping → {"Msg":"服务可用OK", "Time":...}
func pingServer(IP string) error {
	scheme := "http"
	if strings.Contains(IP, ":443") {
		scheme = "https"
	}
	URL := scheme + "://" + IP + "/api/v1/Ping"

	resp, err := http.Post(URL, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if strings.Contains(string(body), "服务可用OK") {
		return nil
	}
	return errors.New("服务器连接不可用")
}

// loadBalancing 负载均衡
func loadBalancing(IP string) (string, error) {
	//判断是否群主服务器
	if IP != LockHost {
		return IP, nil
	}

	ipTemp := "pro.msplock.vip:443"
	err := pingServer(ipTemp)
	if err == nil {
		return ipTemp, nil
	}

	ipTemp = "pro.msplock.vip:8820"
	err = pingServer(ipTemp)
	if err == nil {
		return ipTemp, nil
	}

	return "", errors.New("服务器连接不可用")
}
