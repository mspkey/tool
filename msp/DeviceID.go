package msp

import (
	"fmt"
	"net"
)

type DeviceID struct {
	Mac []string
}

func (c *DeviceID) GetMac() (MacAddress []string) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("fail To get net interfaces: %v", err)
		return MacAddress
	}

	for _, netInterface := range netInterfaces {
		macAddr := netInterface.HardwareAddr.String()
		if len(macAddr) == 0 {
			continue
		}

		MacAddress = append(MacAddress, macAddr)
	}
	return MacAddress
}
