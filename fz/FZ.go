package fz

import (
	"errors"
	"github.com/mspkey/tool/win32"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Memory 内存结果体方法
type Memory struct {
	process int
}

// OpenProcess 打开进程
func (c *Memory) OpenProcess(PID int) error {
	process := win32.OpenProcess(PID)
	c.process = process
	if process == 0 {
		return errors.New("进程打开失败")
	}
	return nil
}

// Close 关闭进程
func (c *Memory) Close() {

	win32.CloseHandle(c.process)

}

// WriteInt 写内存整数型
func (c *Memory) WriteInt(address int, buff int, len int) error {
	err := win32.WriteProcessMemory(c.process, address, unsafe.Pointer(&buff), len)
	if err != nil {
		return err
	}
	return nil
}

// WriteFloat64 写内存双浮点
func (c *Memory) WriteFloat64(address int, buff float64) error {
	err := win32.WriteProcessMemory(c.process, address, unsafe.Pointer(&buff), 8)
	if err != nil {
		return err
	}
	return nil
}

// WriteFloat32 写内存单浮点
func (c *Memory) WriteFloat32(address int, buff float32) error {
	err := win32.WriteProcessMemory(c.process, address, unsafe.Pointer(&buff), 8)
	if err != nil {
		return err
	}
	return nil
}

// WriteBytes 写内存字节集
func (c *Memory) WriteBytes(address int, buff []byte, len int) error {
	err := win32.WriteProcessMemory(c.process, address, unsafe.Pointer(&buff[0]), len)
	if err != nil {
		return err
	}
	return nil
}

// WriteMemory 写内存 用&写入数据 unsafe.Pointer(&buff)
func (c *Memory) WriteMemory(address int, buff unsafe.Pointer, len int) error {

	err := win32.WriteProcessMemory(c.process, address, buff, len)
	if err != nil {
		return err
	}
	return nil

}

// ReadMemory 读内存 用&返回数据 unsafe.Pointer(&buff)
func (c *Memory) ReadMemory(address int, buff unsafe.Pointer, len int) error {
	err := win32.ReadProcessMemory(c.process, address, buff, len)
	if err != nil {
		return err
	}
	return nil
}

// VirtualAllocEx 远程申请内存 返回内存地址 Size->申请的长度
func (c *Memory) VirtualAllocEx(Size int) (int, error) {
	ex, err := win32.VirtualAllocEx(c.process, 0, Size, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return 0, err
	}
	return ex, nil

}

// VirtualProtectEx 修改内存属性
func (c *Memory) VirtualProtectEx(lpAddress int, dwSize int) error {

	var buff int
	buff = 0
	err := win32.VirtualProtectEx(c.process, lpAddress, dwSize, windows.PAGE_READWRITE, unsafe.Pointer(&buff))
	if err != nil {
		return err
	}

	return nil
}

// ReadMemoryIntEx 读内存表达式  [[[xxx]+0x8]+0xc]
func (c *Memory) ReadMemoryIntEx(address []int, len int) int {

	if address == nil {
		return 0
	}
	var Temp int
	for _, item := range address {
		Temp += item
		err := c.ReadMemory(Temp, unsafe.Pointer(&Temp), len)
		if err != nil {
			return 0
		}
	}
	return Temp
}
