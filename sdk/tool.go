package sdk

import (
	"errors"
	"github.com/mspkey/tool/msp"
	"io"
	"net"
	"net/http"
	"strings"
)

// GetDevID 获取设备ID
func GetDevID() string {
	id := msp.DeviceID{}
	address := id.GetMac()
	e := msp.Encrypt{}
	return e.Md5Encrypt(address[0])
}

// pingServer 检测服务器是否可用
func pingServer(IP string) error {
	URL := "http://" + IP + "/ping"
	if strings.Contains(IP, ":443") {
		URL = "https://" + IP + "/ping"
	}

	resp, err := http.Post(URL, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	//fmt.Println(string(body))
	if strings.Contains(string(body), "服务可用OK") {
		return nil
	}
	return nil
}

// ResolveIP  解析域名变IP
func ResolveIP(str string) (string, error) {
	ips, err := net.LookupIP(str)
	if err != nil {
		return "", errors.New("域名解析失败")
	}
	return ips[0].String(), nil
}

// loadBalancing 负载均衡
func loadBalancing(IP string) (string, error) {
	//判断是否群主服务器
	if IP != LockHost {
		return IP, nil
	}

	ipTemp := "v1.msplock.vip:8810"
	err := pingServer(ipTemp)
	if err == nil {
		return ipTemp, nil
	}

	ipTemp = "v2.msplock.vip:8810"
	err = pingServer(ipTemp)
	if err == nil {
		return ipTemp, nil
	}

	var IpList = []string{"v3.msplock.vip", "v4.msplock.vip", "v5.msplock.vip", "v6.msplock.vip", "v7.msplock.vip"}
	//判断服务器状态
	for _, item := range IpList {
		//解析域名变IP
		tempIp, err := ResolveIP(item)
		if err != nil {
			continue
		}

		err = pingServer(tempIp + ":8810")
		if err == nil {
			return tempIp + ":8810", nil
		}
	}

	return "", errors.New("服务器连接不可用")
}
