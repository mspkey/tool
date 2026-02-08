package sdk

import (
	"crypto/rc4"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mspkey/tool/msp"
	"go.mongodb.org/mongo-driver/v2/bson"
	"log"
	"net/http"
	"os"
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
	url       string //连接URL
	conn      *websocket.Conn
	isCoon    bool         //服务器是否连接成功
	res       chan resJson //返回的源数据
	Info      UserInfo     //用户自身信息
	Exe       ExeInfo      //用户绑定的软件
	devKey    string       //通讯密钥
	isLogin   bool         //是否登录
	IsDug     bool         //是否调试信息输出
	variable  string       //远程变量
	config    Config       //配置
	isReset   bool         //断线重连标志 true 时表示断线重连过了 只针对登录的有效
	license   string       //vmp授权
	isAdmin   bool         //是否群主服务器
	writeLock sync.Mutex   //写入锁
	quitHart  chan bool    //退出心跳包
}

func (c *MspKey) IsLogin() bool {
	return c.isLogin
}

// auth 认证
func (c *MspKey) auth() error {
	if !c.isLogin {
		return errors.New("请登录")
	}
	return nil
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
			if c.isReset && c.isLogin {
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
			log.Printf("接受数据:<- %s\n", msg)
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
			msp.ClearScreen()
			log.Println("检测到新版本，请下载新版本")
			if c.Exe.Address != "" {
				log.Println("新版本下载地址:" + c.Exe.Address)
			}
			os.Exit(1)
			return
		}

		//其他
		if data.Tag != "Null" {

			//数据直接解析到全局变量里
			go func() {
				switch data.Tag {
				case tagLogin:
					c.isLogin = true
				case tagCarLogin:
					c.isLogin = true
				case tagExe:
					if v, ok := data.Data.(map[string]any); ok {
						ps := v["Exe"]
						marshal, _ := json.Marshal(ps)
						_ = json.Unmarshal(marshal, &c.Exe)
					}
				case tagUserInfo:

					if v, ok := data.Data.(map[string]any); ok {
						ps := v["UserInfo"]
						marshal, _ := json.Marshal(ps)
						_ = json.Unmarshal(marshal, &c.Info)
					}
				case tagExeData:
					var st struct {
						ExeData string
					}
					marshal, _ := json.Marshal(data.Data)
					_ = json.Unmarshal(marshal, &st)
					c.Exe.Data = st.ExeData
				case tagVariable:
					var st struct {
						ExeData string
					}
					marshal, _ := json.Marshal(data.Data)
					_ = json.Unmarshal(marshal, &st)
					c.variable = st.ExeData
				case tagPing:
					Haunt++
					if c.IsDug {
						log.Println(fmt.Sprintf("收到心跳包,心跳次数:%d", Haunt))
						log.Println(fmt.Sprintf("心跳包数据：%s", data.Msg))
					}
				case tagVMPAuth:
					if v, ok := data.Data.(map[string]any); ok {
						ps := v["License"]
						c.license = ps.(string)
					}
				}

				c.res <- data
			}()

		}

	}

}

// sendData 发送数据
func (c *MspKey) sendData(send sendJson) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	send.Time = fmt.Sprintf("%d", time.Now().Unix())
	marshal, err := json.Marshal(send)
	if err != nil {
		return err
	}
	if c.IsDug {
		log.Println("发送数据:->" + string(marshal))
	}

	msg := rc4EncryptString(c.devKey, string(marshal))
	err = c.conn.WriteMessage(1, []byte(msg))
	if err != nil {
		return err
	}
	//这边需要等待的返回以免数据错乱
	count := 0
	for {
		time.Sleep(time.Millisecond * 300)
		select {
		case temp := <-c.res:
			if temp.Tag == send.Type {
				if temp.Code == 0 {
					return errors.New(temp.Msg)
				} else {
					return nil
				}
			}
		case <-time.After(time.Second * 1):
			if count > 5 {
				return errors.New("等待超时")
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
				err := c.GetExeInfo()
				if err != nil {
					log.Fatalln(err)
				}
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

// Init 验证初始化 ok
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

// GetExeInfo 获取软件基本信息 ok
func (c *MspKey) GetExeInfo() error {

	var p sendJson
	p.Type = tagExe
	return c.sendData(p)
}

// Register 用户注册 ok
func (c *MspKey) Register(Name, Pwd, Code string) error {

	var p sendJson
	p.Type = tagRegister
	p.Data = bson.M{"Name": Name, "Pwd": Pwd, "Code": Code}
	return c.sendData(p)
}

// Login 用户登录 ok
func (c *MspKey) Login(Name, Pwd string) error {

	var p sendJson
	p.Type = tagLogin
	p.Data = bson.M{"Name": Name, "Pwd": Pwd}
	return c.sendData(p)
}

// CarLogin 卡密登录 ok
func (c *MspKey) CarLogin(Serial string) error {

	var p sendJson
	p.Type = tagCarLogin
	p.Data = bson.M{"Serial": Serial}
	err := c.sendData(p)
	if err != nil {
		return err
	}
	c.isLogin = true
	return nil
}

// CkLogin ck登录
func (c *MspKey) CkLogin(CK string) error {

	var p sendJson
	p.Type = tagCkLogin
	p.Data = bson.M{"CK": CK}
	err := c.sendData(p)
	if err != nil {
		return err
	}
	c.isLogin = true
	return nil
}

// UserPay 用户卡密充值 ok
func (c *MspKey) UserPay(Name, Serial string) error {

	var p sendJson
	p.Type = tagUserPay
	p.Data = bson.M{"Name": Name, "Serial": Serial}
	return c.sendData(p)
}

// UpUserPwd 修改密码 ok
func (c *MspKey) UpUserPwd(Name, OldPwd, NewPwd string) error {

	var p sendJson
	p.Type = tagUpUserPwd
	p.Data = bson.M{"Name": Name, "OldPwd": OldPwd, "NewPwd": NewPwd}
	return c.sendData(p)
}

// BindDeviceID 换绑 ok
func (c *MspKey) BindDeviceID(Name, Pwd string) error {

	var p sendJson
	p.Type = tagBindDeviceID
	p.Data = bson.M{"Name": Name, "Pwd": Pwd}
	return c.sendData(p)
}

// AddBlack 加入黑名单
func (c *MspKey) AddBlack(Bak string) error {

	var p sendJson
	p.Type = tagAddBlack
	p.Data = bson.M{"Bak": Bak}
	return c.sendData(p)

}

// GetUserInfo 获取用户信息 ok
func (c *MspKey) GetUserInfo() error {

	err := c.auth()
	if err != nil {
		return err
	}
	var p sendJson
	p.Type = tagUserInfo
	return c.sendData(p)
}

// SetUerConf 设置用户配置信息 ok
func (c *MspKey) SetUerConf(Conf string) error {

	err := c.auth()
	if err != nil {
		return err
	}
	var p sendJson
	p.Type = tagSetUerConf
	p.Data = bson.M{"Conf": Conf}
	return c.sendData(p)

}

// GetExeData 获取核心数据 ok
func (c *MspKey) GetExeData() (string, error) {

	err := c.auth()
	if err != nil {
		return "", err
	}
	var p sendJson
	p.Type = tagExeData
	err = c.sendData(p)
	if err != nil {
		return "", err
	}
	return c.Exe.Data, nil

}

// GetVariable 获取远程变量 ok
func (c *MspKey) GetVariable(Key string) (string, error) {

	err := c.auth()
	if err != nil {
		return "", err
	}
	var p sendJson
	p.Type = tagVariable
	p.Data = bson.M{"Key": Key}
	err = c.sendData(p)
	if err != nil {
		return "", err
	}
	return c.variable, nil
}

// ping 发送心跳包 内部已经完成自动心跳功能
func (c *MspKey) ping() {
	if c.isCoon {
		var p sendJson
		p.Type = tagPing
		//发送检测数据
		data := bson.M{
			"Token": c.getToken(),
			"Key":   c.devKey,
		}
		p.Data = data
		_ = c.sendData(p)
	}

	//判断登陆后是否到期
	if c.Info.Name != "" {
		if c.Info.EndTime.Unix() < time.Now().Unix() {
			log.Fatalln("该账号已到期")
		}

	}

}

// QuickLogin 快速登录
func (c *MspKey) QuickLogin() error {
	//启动UI
	go func() {
		clientUI(c.config.IP)
	}()

	time.Sleep(2 * time.Second)
	//打开网页
	url := fmt.Sprintf("http://localhost:8810/ms/#/WebLogin?DevKey=%s", c.devKey)
	_ = msp.OpenBrowser(url)
	log.Println("网页登录地址:" + url)

	var p sendJson
	p.Type = tagQuick
	index := 0
	for {
		err := c.sendData(p)
		if err != nil {
			if index == 0 {
				log.Println(err)
			}
		} else {
			msp.ClearScreen()
			log.Println(err)
			c.isLogin = true
			return nil
		}
		time.Sleep(time.Second * 3)
		index++
	}
}

// VmpAuth VMP授权下发
func (c *MspKey) VmpAuth() (string, error) {

	err := c.auth()
	if err != nil {
		return "", err
	}
	var p sendJson
	p.Type = tagVMPAuth
	p.Data = bson.M{"HardwareId": c.config.DevID}
	err = c.sendData(p)
	if err != nil {
		return "", err
	}
	return c.license, nil
}

// safe 保护自身
func (c *MspKey) safe() {
	if !c.Exe.IsDbg {
		return
	}
	for {
		time.Sleep(time.Second * 15)
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
