package sdk

import (
	"embed"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/mspkey/tool/msp"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// GetDevID 获取设备ID
func GetDevID() string {
	id := msp.DeviceID{}
	address := id.GetMac()
	e := msp.Encrypt{}
	return e.Md5Encrypt(address[0])
}

//go:embed dist/*
var staticFS embed.FS

// clientUI 后端转发并启动UI
func clientUI(proxyIP string) {

	//判断是否包含":443"端口
	if strings.Contains(proxyIP, ":443") {
		if !strings.Contains(proxyIP, "https") {
			proxyIP = "https://" + proxyIP
		}
	} else {
		//判断是否带有http标识
		if !strings.Contains(proxyIP, "http") {
			proxyIP = "http://" + proxyIP
		}
	}
	// 目标服务器地址
	targetURL, err := url.Parse(proxyIP)
	if err != nil {
		log.Fatal(err)
	}

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host
	}

	// 配置Gin
	gin.DefaultWriter = io.Discard
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()
	r.Use(gin.Recovery())

	// 静态文件服务
	// 获取 dist 子目录的文件系统
	distFS, err := fs.Sub(staticFS, "dist")
	if err != nil {
		panic(err)
	}

	// 获取 assets 子目录的文件系统
	assetsFS, err := fs.Sub(distFS, "assets")
	if err != nil {
		panic(err)
	}

	// 处理 /ms 路由
	r.StaticFS("/ms", http.FS(distFS))

	// 处理 /static 路由
	r.StaticFS("/static", http.FS(assetsFS))

	// API代理
	r.Any("/api/*path", func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	//_ = browser.OpenURL("http://localhost:8810/ms/#/")

	// 启动服务器
	if err := r.Run(":8810"); err != nil {
		log.Fatalf("启动本地UI服务失败: %v", err)
	}
}

// pingServer 检测服务器是否可用
func pingServer(IP string) error {
	URL := "http://" + IP + "/ping"
	if strings.Contains(IP, ":443") {
		URL = "https://" + IP + "/ping"
	}

	resp, err := http.Get(URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	//fmt.Println(string(body))
	if strings.Contains(string(body), "服务可用OK") {
		return nil
	}
	return nil
}

// ResolveIP  解析域名变IP
func ResolveIP(str string) (string, error) {
	ips, err := net.LookupIP(str)
	if err != nil {
		return "", errors.New("域名解析失败")
	}
	return ips[0].String(), nil
}

// loadBalancing 负载均衡
func loadBalancing(IP string) (string, error) {
	//判断是否群主服务器
	if IP != LockHost {
		return IP, nil
	}

	ipTemp := "v1.msplock.vip:443"
	err := pingServer(ipTemp)
	if err == nil {
		return ipTemp, nil
	}

	ipTemp = "v1.msplock.vip:8810"
	err = pingServer(ipTemp)
	if err == nil {
		return ipTemp, nil
	}

	var IpList = []string{"v2.msplock.vip", "v3.msplock.vip", "v4.msplock.vip", "v5.msplock.vip", "v6.msplock.vip", "v7.msplock.vip"}
	//判断服务器状态
	for _, item := range IpList {
		//解析域名变IP
		tempIp, err := ResolveIP(item)
		if err != nil {
			continue
		}

		err = pingServer(tempIp + ":8810")
		if err == nil {
			return tempIp + ":8810", nil
		}
	}

	return "", errors.New("服务器连接不可用")
}
