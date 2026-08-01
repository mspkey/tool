package bin

import (
	"bytes"
	"crypto/md5"
	"embed"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mspkey/tool/msp"
)

type ClientUI struct {
	cmd *exec.Cmd
}

//go:embed ClientUI.exe
var UI embed.FS

const targetPath = `C:\ProgramData\.MspTool\ClientUI.exe`

func (c *ClientUI) CloseUI() {
	if c.cmd != nil && c.cmd.Process != nil {		
		_ = c.cmd.Process.Kill() // 杀死UI进程
	}
}

// Init 初始化
func init() {

	// 判断文件是否已经存在
	if _, err := os.Stat(targetPath); err != nil {
		//文件不存在 进行写入操作
		err := os.MkdirAll(filepath.Dir(targetPath), 0755)
		if err != nil {
			panic("创建目录失败: " + err.Error())
		}

		// 打开嵌入文件
		src, err := UI.Open("ClientUI.exe")
		if err != nil {
			panic(err)
		}
		defer src.Close()

		// 创建目标文件
		dst, err := os.Create(targetPath)
		if err != nil {
			panic(err)
		}
		defer dst.Close()

		// 流式写入（最标准、最安全）
		_, err = io.Copy(dst, src)
		if err != nil {
			panic(err)
		}
		log.Println("<UNK>:" + targetPath)
		return
	}

	//存在就进行md5的对比
	// Start of Selection
	// 读取目标文件并计算MD5
	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		log.Println("读取目标文件失败: " + err.Error())
		return
	}
	targetMD5 := md5.Sum(targetData)

	// 读取嵌入文件并计算MD5
	embedData, err := UI.ReadFile("ClientUI.exe")
	if err != nil {
		log.Println("读取嵌入文件失败: " + err.Error())
		return
	}
	embedMD5 := md5.Sum(embedData)

	// 对比MD5值
	if !bytes.Equal(targetMD5[:], embedMD5[:]) {
		// MD5不一致，重新写入文件
		dst, err := os.Create(targetPath)
		if err != nil {
			log.Println("创建目标文件失败: " + err.Error())
			return
		}
		defer dst.Close()
		if _, err := dst.Write(embedData); err != nil {
			log.Println("写入目标文件失败: " + err.Error())
			return
		}
		log.Println("UI文件MD5不一致，已更新: " + targetPath)
	}
	// End of Selection
}

// WebLogin 网页登录
func (c *ClientUI) WebLogin(Ip, DevKey string) {
	// 初始化UI
	hand := "http://"
	ip := strings.ReplaceAll(Ip, ":443", ":8800")
	ip = strings.ReplaceAll(ip, ":8810", ":8800")
	url := hand + ip + fmt.Sprintf("/#/WebLogin?DevKey=%s", DevKey)
	_ = msp.OpenBrowser(url)
	log.Println("网页登录地址:" + url)
}

// RunLoginUI 启动登录UI
func (c *ClientUI) RunLoginUI(Ip, Devkey string) error {
	//启动UI程序
	c.cmd = exec.Command(targetPath, Ip, Devkey)
	// 隐藏子进程控制台窗口（防止DLL被调用时黑窗口闪烁）
	c.cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	// 启动子进程
	err := c.cmd.Start()
	if err != nil {
		return err
	}
	return nil
}

// RunDownUI 启动下载UI
func (c *ClientUI) RunDownUI(URL, Patch, Name string) error {
	//启动UI程序
	c.cmd = exec.Command(targetPath, "-Update", URL, Patch, Name)
	// 隐藏子进程控制台窗口（防止DLL被调用时黑窗口闪烁）
	c.cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	// 启动子进程
	err := c.cmd.Start()
	if err != nil {
		return err
	}
	return nil
}
