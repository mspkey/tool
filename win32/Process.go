package win32

import (
	"syscall"
	"unsafe"
)

//OpenProcess 打开进程
func OpenProcess(PID int) int {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("OpenProcess")
	handle, _, _ := proc.Call(uintptr(2035711), uintptr(0), uintptr(PID))
	return int(handle)
}

//CloseHandle 关闭进程
func CloseHandle(hProcess int) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("CloseHandle")
	_, _, _ = proc.Call(uintptr(hProcess))

}

// GetProcessId 获取进程ID
func GetProcessId(hProcess int) int {
	dll := syscall.NewLazyDLL("Kernel32.dll")
	proc := dll.NewProc("GetProcessId")
	pid, _, _ := proc.Call(uintptr(hProcess))
	return int(pid)
}

// GetWindowThreadProcessId 获取线程ID和PID标识符
func GetWindowThreadProcessId(HWND int, PID unsafe.Pointer) int {
	dll := syscall.NewLazyDLL("User32.dll")
	proc := dll.NewProc("GetWindowThreadProcessId")
	pid, _, _ := proc.Call(uintptr(HWND), uintptr(PID))
	return int(pid)
}
