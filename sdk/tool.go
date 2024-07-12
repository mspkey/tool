package sdk

import "gitee.com/mspkey/tool/msp"

// GetDevID 获取设备ID
func GetDevID() string {
	id := msp.DeviceID{}
	address := id.GetMac()
	e := msp.Encrypt{}
	return e.Md5Encrypt(address[0])
}
