//go:build !windows

package sdk

// setHidden 非 Windows 平台不支持隐藏属性，静默忽略
func setHidden(string) {}
