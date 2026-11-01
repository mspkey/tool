//go:build windows

package sdk

import "golang.org/x/sys/windows"

// setHidden 设置文件为 Windows 隐藏属性（与 Python SDK 一致）
func setHidden(path string) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.SetFileAttributes(ptr, windows.FILE_ATTRIBUTE_HIDDEN)
}
