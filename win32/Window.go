package win32

import (
	"syscall"
	"unsafe"
)

// FindWindowW 获取窗口句柄
func FindWindowW(ClassName, WinDowName string) int {
	dll := syscall.NewLazyDLL("User32.dll")
	proc := dll.NewProc("FindWindowW")
	fromClassName, _ := syscall.UTF16PtrFromString(ClassName)
	fromWinDowName, _ := syscall.UTF16PtrFromString(WinDowName)

	if ClassName == "" {
		handle, _, _ := proc.Call(uintptr(0), uintptr(unsafe.Pointer(fromWinDowName)))
		return int(handle)
	}
	if WinDowName == "" {
		handle, _, _ := proc.Call(uintptr(unsafe.Pointer(fromClassName)), uintptr(0))
		return int(handle)
	}

	handle, _, _ := proc.Call(uintptr(unsafe.Pointer(fromClassName)), uintptr(unsafe.Pointer(fromWinDowName)))
	return int(handle)
}
