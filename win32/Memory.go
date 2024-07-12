package win32

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

//WriteProcessMemory 写内存 用&写入数据 unsafe.Pointer(&buff) 数组都要用指针的方式unsafe.Pointer(&buff[0])
//ProcessHand 进程句柄
//address 内存地址
//buff 写入数据指针
//len 写入长度
func WriteProcessMemory(hProcess int, address int, buff unsafe.Pointer, len int) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("WriteProcessMemory")
	res, _, _ := proc.Call(uintptr(hProcess), uintptr(address), uintptr(buff), uintptr(len), uintptr(0))
	if res > 0 {
		return nil
	}
	return errors.New(fmt.Sprintf("%X 地址:写入失败", address))
}

//ReadProcessMemory 读内存 用&返回数据 unsafe.Pointer(&buff) 数组都要用指针的方式unsafe.Pointer(&buff[0])
//ProcessHand 进程句柄
//address 内存地址
//buff 读取据指针保存地址
//len 读取长度
func ReadProcessMemory(hProcess int, address int, buff unsafe.Pointer, len int) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("ReadProcessMemory")
	res, _, _ := proc.Call(uintptr(hProcess), uintptr(address), uintptr(buff), uintptr(len), uintptr(0))
	if res > 0 {
		return nil
	}
	return errors.New(fmt.Sprintf("%v 地址:读取失败", address))

}

// VirtualAllocEx 远程申请内存
//hProcess 进程句柄
//lpAddress 预留内存页地址 一般为0
//dwSize  欲分配的内存大小，字节单位；注意实际分 配的内存大小是页内存大小的整数倍
//flAllocationType 内存分配的类型  MEM_COMMIT 0x1000 / 4096
//flProtect  填windows.PAGE_EXECUTE_READWRITE 可读可写可执行 0x4 / 4
func VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect int) (int, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("VirtualAllocEx")
	res, _, _ := proc.Call(uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flAllocationType), uintptr(flProtect))
	if res > 0 {
		return int(res), nil
	}
	return 0, errors.New("内存申请失败")
}

// VirtualProtectEx 修改内存属性
//hProcess 进程句柄
//lpAddress 内存地址
//dwSize  修改的长度
//flAllocationType 新的内存属性   windows.PAGE_READWRITE=4 可读可写 2=只读
//lpflOldProtect   返回原先的内存属性
func VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect int, lpflOldProtect unsafe.Pointer) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("VirtualProtectEx")
	res, _, _ := proc.Call(uintptr(hProcess), uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(lpflOldProtect))
	if res > 0 {
		return nil
	}
	return errors.New("内存属性修改失败")

}
