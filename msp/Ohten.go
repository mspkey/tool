package msp

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)


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

// CompareVersions 版本号对比是否一样 true=一样
func CompareVersions(LocalVersion, RemoteVersion string) bool {
	var LocalZbb, LocalCbb, LocalXbb int //本地版本
	var RemoteZbb, RemoteCbb, RemoteXbb int

	_, err := fmt.Sscanf(LocalVersion, "v%d.%d.%d", &LocalZbb, &LocalCbb, &LocalXbb)
	if err != nil {
		return true
	}
	_, err = fmt.Sscanf(RemoteVersion, "v%d.%d.%d", &RemoteZbb, &RemoteCbb, &RemoteXbb)
	if err != nil {
		return true
	}

	//主版本号对比
	if LocalZbb < RemoteZbb {
		return false
	}
	//次版本号对比
	if LocalCbb < RemoteCbb {
		return false
	}
	//小版本号对比
	if LocalXbb < RemoteXbb {
		return false
	}
	return true
}

// RandomInt 取一个随机数
func RandomInt(min, max int) int {
	// 创建新的随机数生成器，使用当前时间作为种子
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return min + r.Intn(max-min+1)
}

// GetExeMD5 获取软件自身MD5
func GetExeMD5() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(exePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}


// OpenBrowser 跨平台用默认浏览器打开 URL
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}