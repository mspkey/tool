package msp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func OpenBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = []string{url}
	}

	return exec.Command(cmd, args...).Start()
}

// IsEmail 判断是否是邮箱格式 测试成功
func IsEmail(email string) bool {
	return strings.Contains(email, "@")
}

// IsNameAndPwd 用户名或密码5-13位之间
func IsNameAndPwd(Name, Pwd string) (bool, error) {

	if len(Name) < 5 || len(Name) > 13 {
		return false, errors.New("用户名或密码长度5-13位")
	}
	if len(Pwd) < 5 || len(Pwd) > 13 {
		return false, errors.New("用户名或密码长度5-13位")
	}
	return true, nil
}

// ClearScreen 清屏
func ClearScreen() {
	cmd := "clear" // 对于 Windows 系统，使用 "cls"
	if runtime.GOOS == "windows" {
		cmd = "cls"
	}
	cmdRunner := exec.Command(cmd)
	cmdRunner.Stdout = os.Stdout
	cmdRunner.Run()
}

// ClearLastLine 清除一行
func ClearLastLine() {
	fmt.Print("\033[F\033[K") // ANSI escape code to move the cursor up one line and clear the line
}
