package sdk

import (
	"crypto/rc4"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mspkey/tool/msp"
	"go.mongodb.org/mongo-driver/v2/bson"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rc4EncryptString 用rc4进行加密 返回base64 格式数据
func rc4EncryptString(key, strData string) string {
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return ""
	}
	data := make([]byte, len(strData))
	cipher.XORKeyStream(data, []byte(strData))
	encoded := base64.StdEncoding.EncodeToString(data)
	return encoded
}

// rc4DecodeString 用rc4进行解密
func rc4DecodeString(key string, Base64Data string) ([]byte, error) {
	decodeText, err := base64.StdEncoding.DecodeString(Base64Data)
	if err != nil {
		return nil, errors.New("base64 解码失败")
	}
	cipher, err := rc4.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(decodeText))
	cipher.XORKeyStream(output, decodeText)
	return output, nil
}

type MspKey struct {
	url        string //连接URL
	conn       *websocket.Conn
	isCoon     bool         //服务器是否连接成功
	res        chan resJson //返回的源数据
	Info       UserInfo     //用户自身信息
	Exe        ExeInfo      //用户绑定的软件
	devKey     string       //通讯密钥
	IsDug      bool         //是否调试信息输出
	config     Config       //客户配置
	isReset    bool         //断线重连标志 true 时表示断线重连过了 只针对登录的有效
	isAdmin    bool         //是否群主服务器
	writeLock  sync.Mutex   //写入锁
	quitHart   chan bool    //退出心跳包
	AuthData   AuthData     //登录数据
	timeOffSet int64        //时间偏移  服务器时间-本地时间
	HatCount   int64        //心跳计数
}

func (c *MspKey) IsLogin() bool {
	return c.AuthData.IsLogin
}

// GetData 服务器消息返回事件
func (c *MspKey) onMessage() {
	Haunt := 0
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			c.isCoon = false
			log.Println("服务器断开连接")
			//进行断线重连
			if c.isReset && c.AuthData.IsLogin {
				log.Println("断线重连中....")
				go c.RestConn()
			} else {
				log.Fatalln("尚未登录,程序结束")
			}
			c.quitHart <- true
			return
		}
		res := strings.ReplaceAll(string(msg), "\"", "")
		msg, err = rc4DecodeString(c.devKey, res)
		if err != nil {
			continue
		}
		if c.IsDug {
			log.Printf("接受数据:<- %s", msg)
		}

		var data resJson

		err = json.Unmarshal(msg, &data)
		if err != nil {
			log.Println("Error:", err)
			continue
		}

		//防止攻击回放 用于时间戳判断
		p, _ := strconv.ParseInt(data.Time, 10, 64)
		if p <= time.Now().Unix() {
			log.Fatalln("校验失败,数据已过期")
			return
		}

		//动态密钥替换操作
		if data.Tag == tagDevKey {
			c.devKey = fmt.Sprintf("%s", data.Data)
			sec, _ := strconv.ParseInt(data.Time, 10, 64)
			c.timeOffSet = sec - time.Now().Unix()
			continue
		}

		//实时消息
		if data.Tag == "SendMsg" && data.Code == 1 {
			log.Println("收到一条实时消息:" + data.Msg)
			continue
		}

		//主动下线
		if data.Tag == "OffLine" && data.Code == 1 {
			log.Fatalln(data.Msg)
			return
		}

		//是否强制更新
		if data.Tag == "UpDate" && data.Code == 0 {
			c.Exe, err = c.GetExeInfo()
			if err != nil {
				log.Println(err)
			}
			msp.ClearScreen()
			log.Println("检测到新版本，请下载新版本")
			if c.Exe.Address != "" {
				log.Println("新版本下载地址:" + c.Exe.Address)
			}
			os.Exit(1)
			return
		}

		if data.Tag == tagPing {
			Haunt++
			if c.IsDug {
				log.Println(fmt.Sprintf("收到心跳包,心跳次数:%d", Haunt))
				log.Println(fmt.Sprintf("心跳包数据：%s", data.Msg))
			}
		}

		//其他 自己进行解析
		if data.Tag != "Null" {
			c.res <- data
		}

	}

}

// sendData 发送数据
func (c *MspKey) sendData(send sendJson) (resJson, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	send.Time = fmt.Sprintf("%d", time.Now().Unix())
	marshal, err := json.Marshal(send)
	if err != nil {
		return resJson{}, err
	}
	if c.IsDug {
		log.Println("发送数据:->" + string(marshal))
	}

	msg := rc4EncryptString(c.devKey, string(marshal))
	err = c.conn.WriteMessage(1, []byte(msg))
	if err != nil {
		return resJson{}, err
	}
	//这边需要等待的返回以免数据错乱
	count := 0
	for {
		time.Sleep(time.Millisecond * 300)
		select {
		case temp := <-c.res:
			if temp.Tag == send.Type {
				if temp.Code == 0 {
					return resJson{}, errors.New(temp.Msg)
				} else {
					return temp, nil
				}
			}
		case <-time.After(time.Second * 1):
			if count > 5 {
				return resJson{}, errors.New("等待超时")
			}
			count++
		}

	}

}

// connectServer 连接服务器 内部不能包含结束程序指令
func (c *MspKey) connectServer() error {

	if strings.Contains(c.config.IP, ":443") {
		c.url = fmt.Sprintf("wss://%s/api/user/ws", c.config.IP)
	} else {
		c.url = fmt.Sprintf("ws://%s/api/user/ws", c.config.IP)
	}

	//兜底清除异常连接
	if c.devKey != "" {
		c.reportConnStatus()
	}

	key := msp.GetRandomString(6)
	c.devKey = key //默认密钥

	// 创建自定义的 HTTP Header
	header := http.Header{}
	header.Set("Key", base64.StdEncoding.EncodeToString([]byte(c.devKey))) // 添加自定义头部
	str := bson.M{
		"ExeID": c.config.ExeID,
		"DevID": c.config.DevID,
	}
	marshal, err := json.Marshal(str)
	if err != nil {
		return err
	}
	header.Set("Data", base64.StdEncoding.EncodeToString(marshal)) // 添加自定义头部

	c.conn, _, err = websocket.DefaultDialer.Dial(c.url, header)
	if err != nil {
		return errors.New("服务器连接失败")
	}

	go c.onMessage()
	count := 0
	for {
		if c.devKey != key {
			c.isReset = true
			//启动心跳包
			go func() {
				//服务器链接成功
				c.isCoon = true
				//先发一次心跳包 用于检测版本等信息
				c.ping()
				//启动检测
				go c.safe()
				for {
					select {
					case <-c.quitHart:
						if c.IsDug {
							log.Println("退出心跳包")
						}
						return
					case <-time.After(time.Second * 60):
						if c.isCoon {
							c.ping()
						}
					}

				}
			}()
			return nil
		}
		if count > 10 {
			return errors.New("等待超时")
		}
		count++
		time.Sleep(time.Second)
	}
}

// Init 验证初始化
func (c *MspKey) Init(Config Config) error {
	c.config = Config
	//判断是否群主服务器
	if c.config.IP == LockHost {
		c.isAdmin = true
	}
	//负载均衡
	balancing, err := loadBalancing(c.config.IP)
	if err != nil {
		log.Fatalln(err)
	} else {
		c.config.IP = balancing
	}

	if c.res == nil {
		c.res = make(chan resJson, 1)
	}
	if c.quitHart == nil {
		c.quitHart = make(chan bool, 1)
	}
	err = c.connectServer()
	if err != nil {
		return err
	}

	//获取软件信息,用于之后的各种调用
	_, _ = c.GetExeInfo()
	return nil
}

// RestConn 断线重连操作
func (c *MspKey) RestConn() {

	//等待30-60秒
	t := msp.RandomInt(30, 60)
	time.Sleep(time.Duration(t))
	//判断是否群主服务器
	if c.isAdmin {
		c.config.IP = LockHost
	}
	//负载均衡
	balancing, err := loadBalancing(c.config.IP)
	if err != nil {
		log.Fatalln(err)
	} else {
		c.config.IP = balancing
	}

	count := 3
	for {
		log.Println(fmt.Sprintf("第%d次断线重连", count+1))
		time.Sleep(time.Second * time.Duration(count))
		err = c.connectServer()
		if err != nil {
			if count > 360 {
				if c.Exe.IsSafeQuit {
					return
				}
				log.Fatalln("断线重连失败")
			}
			count++
			continue
		}
		log.Println("断线重连成功,自动登录中...")
		break
	}

	//需要ck自动登录
	time.Sleep(time.Second)
	for {
		if c.Info.Name != "" {
			err = c.CkLogin(c.Info.ID.Hex())
			if err != nil {
				log.Fatalln(err)
			} else {
				log.Println("自动登录成功")
				break
			}
		} else {
			log.Fatalln("尚未登录")
		}
	}
}

// GetExeInfo 获取软件基本信息ok
func (c *MspKey) GetExeInfo() (ExeInfo, error) {

	var p sendJson
	p.Type = tagExe
	data, err := c.sendData(p)
	if err != nil {
		return ExeInfo{}, err
	}
	//需要解析exe数据  复用到全局上
	var exe struct {
		Exe ExeInfo `json:"Exe"`
	}
	marshal, err := json.Marshal(data.Data)
	if err != nil {
		return ExeInfo{}, err
	}
	err = json.Unmarshal(marshal, &exe)
	if err != nil {
		return ExeInfo{}, err
	}
	c.Exe = exe.Exe
	return c.Exe, nil
}

// Register 用户注册ok
func (c *MspKey) Register(Name, Pwd, Code string) error {

	var p sendJson
	p.Type = tagRegister
	p.Data = bson.M{"Name": Name, "Pwd": Pwd, "Code": Code}
	_, err := c.sendData(p)
	if err != nil {
		return err
	}
	return nil
}

// Login 用户登录ok
func (c *MspKey) Login(Name, Pwd string) error {

	var p sendJson
	p.Type = tagLogin
	p.Data = bson.M{"Name": Name, "Pwd": Pwd}
	res, err := c.sendData(p)
	if err != nil {
		return err
	}
	return c.AuthDataParse(res.Data)
}

// CarLogin 卡密登录ok
func (c *MspKey) CarLogin(Serial string) error {

	var p sendJson
	p.Type = tagCarLogin
	p.Data = bson.M{"Serial": Serial}
	res, err := c.sendData(p)
	if err != nil {
		return err
	}
	return c.AuthDataParse(res.Data)
}

// CkLogin ck登录ok
func (c *MspKey) CkLogin(CK string) error {

	var p sendJson
	p.Type = tagCkLogin
	p.Data = bson.M{"CK": CK}
	res, err := c.sendData(p)
	if err != nil {
		return err
	}
	return c.AuthDataParse(res.Data)
}

// UserPay 用户卡密充值ok
func (c *MspKey) UserPay(Name, Serial string) error {

	var p sendJson
	p.Type = tagUserPay
	p.Data = bson.M{"Name": Name, "Serial": Serial}
	_, err := c.sendData(p)
	if err != nil {
		return err
	}
	return nil
}

// UpUserPwd 修改密码ok
func (c *MspKey) UpUserPwd(Name, OldPwd, NewPwd string) error {

	var p sendJson
	p.Type = tagUpUserPwd
	p.Data = bson.M{"Name": Name, "OldPwd": OldPwd, "NewPwd": NewPwd}
	_, err := c.sendData(p)
	if err != nil {
		return err
	}
	return nil
}

// BindDeviceID 换绑ok
func (c *MspKey) BindDeviceID(Name, Pwd string) error {

	var p sendJson
	p.Type = tagBindDeviceID
	p.Data = bson.M{"Name": Name, "Pwd": Pwd}
	_, err := c.sendData(p)
	if err != nil {
		return err
	}
	return nil
}

// AddBlack 加入黑名单ok
func (c *MspKey) AddBlack(Bak string) error {

	var p sendJson
	p.Type = tagAddBlack
	p.Data = bson.M{"Bak": Bak}
	_, err := c.sendData(p)
	if err != nil {
		return err
	}
	return nil

}

// GetUserInfo 获取用户信息ok
func (c *MspKey) GetUserInfo() (UserInfo, error) {
	if !c.AuthData.IsLogin {
		return UserInfo{}, errors.New("请先登录>>>")
	}
	var p sendJson
	p.Type = tagUserInfo
	res, err := c.sendData(p)
	if err != nil {
		return UserInfo{}, err
	}

	var u struct {
		UserInfo UserInfo `json:"UserInfo"`
	}
	marshal, err := json.Marshal(res.Data)
	if err != nil {
		return UserInfo{}, err
	}
	err = json.Unmarshal(marshal, &u)
	if err != nil {
		return UserInfo{}, err
	}
	c.Info = u.UserInfo
	//进行到期时间的更新
	c.AuthData.EndTime = c.Info.EndTime
	return c.Info, nil
}

// SetUerConf 设置用户配置信息 ok
func (c *MspKey) SetUerConf(Conf string) error {

	if !c.AuthData.IsLogin {
		return errors.New("请先登录>>>")
	}

	var p sendJson
	p.Type = tagSetUerConf
	p.Data = bson.M{"Conf": Conf}
	_, err := c.sendData(p)
	if err != nil {
		return err
	}
	return nil

}

// GetExeData 获取核心数据ok
func (c *MspKey) GetExeData() (string, error) {

	if !c.AuthData.IsLogin {
		return "", errors.New("请先登录>>>")
	}
	var p sendJson
	p.Type = tagExeData
	res, err := c.sendData(p)
	if err != nil {
		return "", err
	}
	var data struct {
		ExeData string `json:"ExeData"`
	}
	marshal, err := json.Marshal(res.Data)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(marshal, &data)
	if err != nil {
		return "", err
	}
	return data.ExeData, nil

}

// GetVariable 获取远程变量ok
func (c *MspKey) GetVariable(Key string) (string, error) {

	if !c.AuthData.IsLogin {
		return "", errors.New("请先登录>>>")
	}
	var p sendJson
	p.Type = tagVariable
	p.Data = bson.M{"Key": Key}
	res, err := c.sendData(p)
	if err != nil {
		return "", err
	}

	var data struct {
		ExeData string `json:"ExeData"`
	}
	marshal, err := json.Marshal(res.Data)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(marshal, &data)
	if err != nil {
		return "", err
	}
	return data.ExeData, nil
}

// ping 发送心跳包 内部已经完成自动心跳功能
func (c *MspKey) ping() {
	if c.isCoon {
		var p sendJson
		p.Type = tagPing
		//发送检测数据 10分钟进行检测一次
		if c.HatCount%10 == 0 || c.HatCount == 0 {
			data := bson.M{
				"Token": c.getToken(),
				"Key":   c.devKey,
			}
			p.Data = data
		}
		c.HatCount++
		_, _ = c.sendData(p)
	}

	//判断登陆后是否到期
	if c.AuthData.IsLogin {
		if c.AuthData.EndTime.Unix() < time.Now().Unix()+c.timeOffSet {
			log.Fatalln("该账号已到期")
		}

	}
}

//go:embed bin/ClientUI.exe
var UI embed.FS

// QuickLogin 快速登录ok
func (c *MspKey) QuickLogin() error {
	var cmd *exec.Cmd

	//判断是否网页登录
	if c.Exe.IsWebLogin {
		hand := "http://"
		ip := strings.ReplaceAll(c.config.IP, ":443", ":8800")
		ip = strings.ReplaceAll(ip, ":8810", ":8800")
		url := hand + ip + fmt.Sprintf("/#/WebLogin?DevKey=%s", c.devKey)
		_ = msp.OpenBrowser(url)
		log.Println("网页登录地址:" + url)
	} else {

		targetPath := `C:\ProgramData\.MspTool\ClientUI.exe`

		// 判断文件是否已经存在
		if _, err := os.Stat(targetPath); err != nil {
			//文件不存在 进行写入操作
			err := os.MkdirAll(filepath.Dir(targetPath), 0755)
			if err != nil {
				panic("创建目录失败: " + err.Error())
			}

			// 打开嵌入文件
			src, err := UI.Open("bin/ClientUI.exe")
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

		}

		//启动UI程序
		cmd = exec.Command(targetPath, c.config.IP, c.devKey)

		// 启动子进程
		err := cmd.Start()
		if err != nil {
			panic("启动失败: " + err.Error())
		}
	}

	time.Sleep(2 * time.Second)
	//打开网页

	var p sendJson
	p.Type = tagQuick
	index := 0
	for {
		if !c.Exe.IsWebLogin {
			//判断UI进程是否存在  不存在就退出
			cmd := exec.Command("cmd", "/C", "tasklist")
			output, err := cmd.Output()
			if err != nil {
				return err
			}
			// 检查输出中是否包含目标进程名称
			if !strings.Contains(string(output), "ClientUI.exe") {
				return errors.New("UI关闭,程序退出")
			}

		}

		res, err := c.sendData(p)
		if err != nil {
			if index == 0 {
				log.Println(err)
			}
		} else {
			err := c.AuthDataParse(res.Data)
			if err != nil {
				return err
			}
			msp.ClearScreen()
			if !c.Exe.IsWebLogin {
				//关闭UI进程
				if cmd != nil && cmd.Process != nil {
					log.Println("登录成功，关闭UI进程")
					_ = cmd.Process.Kill() // 杀死UI进程
				}
			}

			return nil
		}
		time.Sleep(time.Second * 3)
		index++
	}
}

// VmpAuth VMP授权下发ok
func (c *MspKey) VmpAuth() (string, error) {
	if !c.AuthData.IsLogin {
		return "", errors.New("请先登录>>>")
	}
	var p sendJson
	p.Type = tagVMPAuth
	p.Data = bson.M{"HardwareId": c.config.DevID}
	res, err := c.sendData(p)
	if err != nil {
		return "", err
	}

	var data struct {
		License string `json:"License"`
	}
	marshal, err := json.Marshal(res.Data)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(marshal, &data)
	if err != nil {
		return "", err
	}

	return data.License, nil
}

// safe 保护自身
func (c *MspKey) safe() {
	if !c.Exe.IsDbg {
		return
	}
	for {
		time.Sleep(time.Second * 60)
		if c.Exe.AdminID.Hex() != c.config.AdminKey {
			log.Fatalln("密钥错误")
		}
		if !c.isCoon {
			return
		}
	}
}

// getToken 获取token
func (c *MspKey) getToken() string {
	data := bson.M{
		"ExeID":   c.config.ExeID,
		"DevID":   c.config.DevID,
		"Version": c.config.Version,
		"ExeMD5":  c.config.ExeMD5,
		"AdminID": c.config.AdminKey,
		"Time":    fmt.Sprintf("%d", time.Now().Unix()),
		"CRCOld":  "",
		"CRCNew":  "",
	}
	marshal, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	msg := rc4EncryptString(c.devKey, string(marshal))
	return msg
}

// reportConnStatus 上报退出状态
func (c *MspKey) reportConnStatus() {
	URL := "http://" + c.config.IP + "/api/user/ReportConnStatus?DevKey=" + c.devKey
	if strings.Contains(c.config.IP, ":443") {
		URL = "https://" + c.config.IP + "/api/user/ReportConnStatus?DevKey=" + c.devKey
	}

	_, _ = http.Post(URL, "application/json", nil)
	return
}

// createSN()
func (c *MspKey) createSN(Sig string) string {
	md5 := msp.Encrypt{}
	str := c.devKey + c.config.DevID + c.config.ExeID + c.config.AdminKey + Sig
	return md5.Md5Encrypt(str)
}

// AuthDataParse  数据进行解析并保存到类内,内部自动判断是否到期
func (c *MspKey) AuthDataParse(Data any) error {

	Aec := msp.Encrypt{}
	Key := c.config.AdminKey + c.devKey[:8]

	data, ok := Data.(string)
	if !ok {
		return errors.New("数据类型错误")
	}

	decrypt, err := Aec.Aes256CbcDecrypt(data, []byte(Key))
	if err != nil {
		return err
	}

	var Auth struct {
		UserID  string `json:"UserID"`  //用户ID 用于CK登录
		EndTime string `json:"EndTime"` //用户到期时间
		IsLogin bool   `json:"IsLogin"` //是否登录
		SN      string `json:"SN"`      //用于校验
		Sig     string `json:"Sig"`
	}

	err = json.Unmarshal(decrypt, &Auth)
	if err != nil {
		return err
	}
	sec, err := strconv.ParseInt(Auth.EndTime, 10, 64)
	if err != nil {
		return err
	}
	c.AuthData.EndTime = time.Unix(sec, 0)
	c.AuthData.UserID = Auth.UserID
	c.AuthData.SN = Auth.SN
	c.AuthData.IsLogin = Auth.IsLogin
	c.AuthData.Sig = Auth.Sig

	//校验SN码
	if c.createSN(c.AuthData.Sig) != c.AuthData.SN {
		return errors.New("SN码校验失败")
	}

	//判断到期时间
	if c.AuthData.EndTime.Unix() < time.Now().Unix()+c.timeOffSet {
		return errors.New("账号已过期")
	}

	return nil
}
