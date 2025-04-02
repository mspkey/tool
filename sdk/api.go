package sdk

import (
	"crypto/rc4"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/mspkey/tool/msp"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	url      string //连接URL
	conn     *websocket.Conn
	state    bool     //服务器是否连接成功
	res      resJson  //返回的源数据
	Info     UserInfo //用户自身信息
	Exe      ExeInfo  //用户绑定的软件
	devKey   string   //通讯密钥
	isLogin  bool     //是否登录
	IsDug    bool     //是否调试信息输出
	variable string   //远程变量
	config   Config
	isReset  bool //断线重连标志 true 时表示断线重连过了 只针对登录的有效
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

// ClearRes 清空接受信息
func (c *MspKey) ClearRes() {
	c.res = resJson{}
}

// aWaitRes 等待返回
func (c *MspKey) aWaitRes(Tag string) error {
	count := 0
	for {
		time.Sleep(time.Millisecond * 300)
		if c.res.Tag == Tag {
			if c.res.Code == 0 {
				return errors.New(c.res.Msg)
			} else {
				return nil
			}
		}
		if count > 30 {
			return errors.New("超时")
		}
		count++
	}
}

// GetData 服务器消息返回事件
func (c *MspKey) onMessage() {
	Haunt := 0
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			c.state = false
			log.Println("服务器断开连接")
			//进行断线重连
			if c.isReset {
				log.Println("断线重连中....")
				go c.RestConn()
			}
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
		err = json.Unmarshal(msg, &c.res)
		if err != nil {
			log.Println("Error:", err)
			continue
		}

		//防止攻击回放 用于时间戳判断
		p, _ := strconv.ParseInt(c.res.Time, 10, 64)
		if p <= time.Now().Unix() {
			log.Fatalln("校验失败,数据已过期")
			return
		}

		//动态密钥替换操作
		if c.res.Tag == tagDevKey {
			c.devKey = fmt.Sprintf("%s", c.res.Data)
			//启动心跳包
			go func() {
				err := c.GetExeInfo()
				if err != nil {
					log.Fatalln(err)
				}
				c.state = true
				//先发一次心跳包 用于检测版本等信息
				c.ping()
				//启动检测
				go c.safe()

				for {
					time.Sleep(time.Second * 60)
					c.ping()
					if !c.state {
						return
					}
				}
			}()
			continue
		}

		//实时消息
		if c.res.Tag == "SendMsg" && c.res.Code == 1 {
			log.Println("收到一条实时消息:" + c.res.Msg)
			continue
		}

		//主动下线
		if c.res.Tag == "OffLine" && c.res.Code == 1 {
			log.Fatalln(c.res.Msg)
			return
		}

		//是否强制更新
		if c.res.Tag == "UpDate" && c.res.Code == 0 {
			msp.ClearScreen()
			log.Println("检测到新版本，请下载新版本")
			if c.Exe.Address != "" {
				log.Println("新版本下载地址:" + c.Exe.Address)
			}
			os.Exit(1)
			return
		}

		//其他
		if c.res.Tag != "Null" {

			//数据直接解析到全局变量里
			go func() {
				switch c.res.Tag {
				case tagLogin:
					c.isLogin = true
				case tagCarLogin:
					c.isLogin = true
				case tagExe:
					if v, ok := c.res.Data.(map[string]any); ok {
						ps := v["Exe"]
						marshal, _ := json.Marshal(ps)
						_ = json.Unmarshal(marshal, &c.Exe)
					}
				case tagUserInfo:

					if v, ok := c.res.Data.(map[string]any); ok {
						ps := v["UserInfo"]
						marshal, _ := json.Marshal(ps)
						_ = json.Unmarshal(marshal, &c.Info)
					}
				case tagExeData:
					var st struct {
						ExeData string
					}
					marshal, _ := json.Marshal(c.res.Data)
					_ = json.Unmarshal(marshal, &st)
					c.Exe.Data = st.ExeData
				case tagVariable:
					var st struct {
						ExeData string
					}
					marshal, _ := json.Marshal(c.res.Data)
					_ = json.Unmarshal(marshal, &st)
					c.variable = st.ExeData
				case tagPing:
					Haunt++
					if c.IsDug {
						log.Println(fmt.Sprintf("收到心跳包,心跳次数:%d", Haunt))
						log.Println(fmt.Sprintf("心跳包数据：%s", c.res.Msg))
					}
				}

			}()

		}

	}

}

// sendData 发送数据
func (c *MspKey) sendData(data sendJson) {
	data.Time = fmt.Sprintf("%d", time.Now().Unix())
	marshal, err := json.Marshal(data)
	if err != nil {
		return
	}
	if c.IsDug {
		log.Println("发送数据:->" + string(marshal))
	}

	msg := rc4EncryptString(c.devKey, string(marshal))
	err = c.conn.WriteMessage(1, []byte(msg))
	if err != nil {
		return
	}

}

// Init 验证初始化 ok
func (c *MspKey) Init(Config Config) error {
	c.config = Config
	key := msp.GetRandomString(6)
	c.devKey = key //默认密钥
	c.url = fmt.Sprintf("ws://%s/api/user/ws?ExeID=%s&DevID=%s", Config.IP, Config.ExeID, Config.DevID)
	var err error
	count := 0

	// 创建自定义的 HTTP Header
	header := http.Header{}
	header.Set("Key", base64.StdEncoding.EncodeToString([]byte(c.devKey))) // 添加自定义头部
	log.Println(header)
	c.conn, _, err = websocket.DefaultDialer.Dial(c.url, header)
	if err != nil {
		log.Fatalln("服务器连接失败")
	}
	log.Println("服务器连接成功")
	go c.onMessage()

	for {
		if c.devKey != key {
			c.isReset = true
			return nil
		}
		if count > 10 {
			return errors.New("等待超时")
		}
		count++
		time.Sleep(time.Second)
	}

}

// RestConn 断线重连操作
func (c *MspKey) RestConn() {
	key := msp.GetRandomString(6)
	c.devKey = key
	var err error
	count := 0
	for {
		log.Println(fmt.Sprintf("第%d次断线重连", count+1))
		time.Sleep(time.Second * 3)
		header := http.Header{}
		header.Add("Key", base64.StdEncoding.EncodeToString([]byte(c.devKey))) // 添加自定义头部
		c.conn, _, err = websocket.DefaultDialer.Dial(c.url, header)

		if err != nil {
			if count > 200 {
				log.Fatalln("断线重连失败")
			}
			count++
			continue
		}
		log.Println("断线重连成功,自动登录中...")
		break
	}

	go c.onMessage()

	//需要ck自动登录
	time.Sleep(time.Second)
	for {
		if c.devKey != key {
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

}

// GetExeInfo 获取软件基本信息 ok
func (c *MspKey) GetExeInfo() error {
	c.ClearRes()
	var p sendJson
	p.Type = tagExe
	c.sendData(p)
	return c.aWaitRes(p.Type)
}

// Register 用户注册 ok
func (c *MspKey) Register(Name, Pwd, Code string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagRegister
	p.Data = bson.M{"Name": Name, "Pwd": Pwd, "Code": Code}
	c.sendData(p)
	return c.aWaitRes(p.Type)
}

// Login 用户登录 ok
func (c *MspKey) Login(Name, Pwd string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagLogin
	p.Data = bson.M{"Name": Name, "Pwd": Pwd}
	c.sendData(p)
	return c.aWaitRes(p.Type)
}

// CarLogin 卡密登录 ok
func (c *MspKey) CarLogin(Serial string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagCarLogin
	p.Data = bson.M{"Serial": Serial}
	c.sendData(p)
	err := c.aWaitRes(p.Type)
	if err != nil {
		return err
	}
	c.isLogin = true
	return nil
}

// CkLogin ck登录
func (c *MspKey) CkLogin(CK string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagCkLogin
	p.Data = bson.M{"CK": CK}
	c.sendData(p)
	err := c.aWaitRes(p.Type)
	if err != nil {
		return err
	}
	c.isLogin = true
	return nil
}

// UserPay 用户卡密充值 ok
func (c *MspKey) UserPay(Name, Serial string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagUserPay
	p.Data = bson.M{"Name": Name, "Serial": Serial}
	c.sendData(p)
	return c.aWaitRes(p.Type)
}

// UpUserPwd 修改密码 ok
func (c *MspKey) UpUserPwd(Name, OldPwd, NewPwd string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagUpUserPwd
	p.Data = bson.M{"Name": Name, "OldPwd": OldPwd, "NewPwd": NewPwd}
	c.sendData(p)
	return c.aWaitRes(p.Type)
}

// BindDeviceID 换绑 ok
func (c *MspKey) BindDeviceID(Name, Pwd string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagBindDeviceID
	p.Data = bson.M{"Name": Name, "Pwd": Pwd}
	c.sendData(p)
	return c.aWaitRes(p.Type)
}

// AddBlack 加入黑名单
func (c *MspKey) AddBlack(Bak string) error {
	c.ClearRes()
	var p sendJson
	p.Type = tagAddBlack
	p.Data = bson.M{"Bak": Bak}
	c.sendData(p)
	return c.aWaitRes(p.Type)

}

// GetUserInfo 获取用户信息 ok
func (c *MspKey) GetUserInfo() error {
	c.ClearRes()
	err := c.auth()
	if err != nil {
		return err
	}
	var p sendJson
	p.Type = tagUserInfo
	c.sendData(p)
	return c.aWaitRes(p.Type)
}

// SetUerConf 设置用户配置信息 ok
func (c *MspKey) SetUerConf(Conf string) error {
	c.ClearRes()
	err := c.auth()
	if err != nil {
		return err
	}
	var p sendJson
	p.Type = tagSetUerConf
	p.Data = bson.M{"Conf": Conf}
	c.sendData(p)
	return c.aWaitRes(p.Type)

}

// GetExeData 获取核心数据 ok
func (c *MspKey) GetExeData() (string, error) {
	c.ClearRes()
	err := c.auth()
	if err != nil {
		return "", err
	}
	var p sendJson
	p.Type = tagExeData
	c.sendData(p)
	err = c.aWaitRes(p.Type)
	if err != nil {
		return "", err
	}
	return c.Exe.Data, nil

}

// GetVariable 获取远程变量 ok
func (c *MspKey) GetVariable(Key string) (string, error) {
	c.ClearRes()
	err := c.auth()
	if err != nil {
		return "", err
	}
	var p sendJson
	p.Type = tagVariable
	p.Data = bson.M{"Key": Key}
	c.sendData(p)
	err = c.aWaitRes(p.Type)
	if err != nil {
		return "", err
	}
	return c.variable, nil
}

// ping 发送心跳包 内部已经完成自动心跳功能
func (c *MspKey) ping() {
	if c.state {
		var p sendJson
		p.Type = tagPing
		//发送检测数据
		data := bson.M{
			"Token": c.getToken(),
			"Key":   c.devKey,
		}
		p.Data = data
		c.sendData(p)
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
	//打开网页
	url := fmt.Sprintf("http://%s/#/WebLogin?DevKey=%s", strings.ReplaceAll(c.config.IP, "8810", "8800"), c.devKey)
	_ = msp.OpenBrowser(url)
	log.Println("网页登录地址:" + url)
	c.ClearRes()
	var p sendJson
	p.Type = tagQuick
	index := 0
	for {
		c.sendData(p)
		err := c.aWaitRes(p.Type)
		if err != nil {
			if index == 0 {
				log.Println(c.res.Msg)
			}
		} else {
			msp.ClearScreen()
			log.Println(c.res.Msg)
			c.isLogin = true
			return nil
		}
		time.Sleep(time.Second * 3)
		index++
	}
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
		if !c.state {
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
