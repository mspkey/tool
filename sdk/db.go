package sdk

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"time"
)

const LockHost = "127.0.0.1:8810"

type resJson struct {
	Tag  string `json:"Tag" bson:"Tag"`
	Code int    `json:"Code" bson:"Code"`
	Msg  string `json:"Msg" bson:"Msg"`
	Data any    `json:"Data" bson:"Data"`
	Time string `json:"Time" bson:"Time"`
}

type sendJson struct {
	Type string `json:"Type" bson:"Type"`
	Data any    `json:"Data" bson:"Data"`
	Time string `json:"Time"`
}

type Config struct {
	IP       string //服务器IP
	ExeID    string //软件ID
	Version  string //当前版本
	DevID    string //设备ID
	AdminKey string //密钥
	ExeMD5   string //软件的md5值
}

// ExeInfo 软件
type ExeInfo struct {
	ID              bson.ObjectID      `json:"ID" bson:"_id"`                           //软件ID
	AdminID         bson.ObjectID `json:"AdminID"  bson:"AdminID"`                 //绑定管理员ID
	Title           string             `json:"Title"  bson:"Title"`                     //软件标题
	Versions        string             `json:"Versions"  bson:"Versions"`               //版本
	State           bool               `json:"State"  bson:"State"`                     //状态 正常/禁用
	Notice          string             `json:"Notice"  bson:"Notice"`                   //公告
	Address         string             `json:"Address"  bson:"Address"`                 //更新地址
	Md5             string             `json:"Md5"  bson:"Md5"`                         //软件MD5
	Data            string             `json:"Data"  bson:"Data"`                       //软件核心数据
	Key             string             `json:"Key"  bson:"Key"`                         //密钥
	IsWebLogin      bool               `json:"IsWebLogin" bson:"IsWebLogin"`            //是否使用网页登录
	IsSafeQuit      bool               `json:"IsSafeQuit" bson:"IsSafeQuit"`            //是否安全退出
	IsDK            bool               `json:"IsDK"  bson:"IsDK"`                       //是否多开
	IsReg           bool               `json:"IsReg"  bson:"IsReg"`                     //是否允许注册
	IsDbg           bool               `json:"IsDbg"  bson:"IsDbg"`                     //是否开启检测
	IsBindIP        bool               `json:"IsBindIP"  bson:"IsBindIP"`               //是否绑定IP
	IsDeviceID      bool               `json:"IsDeviceID"  bson:"IsDeviceID"`           //是否绑定设备ID
	IsUpDate        bool               `json:"IsUpDate" bson:"IsUpDate"`                //是否强制更新软件
	GiveTime        int64              `json:"GiveTime"  bson:"GiveTime"`               //软件注册赠送时间 分钟
	BindCount       int64              `json:"BindCount"  bson:"BindCount"`             //设置换绑次数 次/天
	SubTime         int64              `json:"SubTime" bson:"SubTime"`                  //换绑扣时间 单位/小时
	BindDeviceIDNum int64              `json:"BindDeviceIDNum"  bson:"BindDeviceIDNum"` //同一软件同一设备用户注册数量限制
	LoginMod        int64              `json:"LoginMod"  bson:"LoginMod"`               //登录模式0=单卡+用户 1=用户登录 2=单卡登录
}

// Car 卡密结构
type Car struct {
	ID        bson.ObjectID `json:"ID" bson:"_id"`              //卡ID
	AdminID   bson.ObjectID `json:"AdminID" bson:"AdminID"`     //绑定管理员ID
	ExeID     bson.ObjectID `json:"ExeID" bson:"ExeID"`         //软件ID
	Serial    string             `json:"Serial" bson:"Serial"`       //卡号
	State     bool               `json:"State" bson:"State"`         //状态 正常/禁用
	TyCar     int64              `json:"TyCar" bson:"TyCar"`         //卡密类型  0=小时卡 1=天卡 2=周卡 3=月卡 4=季卡 5=半年卡 6=年卡 7=永久卡
	Price     float64            `json:"Price" bson:"Price"`         //售价
	Bak       string             `json:"Bak" bson:"Bak"`             //备注
	Lock      bool               `json:"Lock" bson:"Lock"`           //锁定卡密不能被删除和获取
	BillID    string             `json:"BillID" bson:"BillID"`       //支付宝交易号
	CreatTime time.Time          `json:"CreatTime" bson:"CreatTime"` //制卡时间
}

// UserInfo 用户
type UserInfo struct {
	ID            bson.ObjectID `json:"ID" bson:"_id"`                      //用户ID
	AdminID       bson.ObjectID `json:"AdminID" bson:"AdminID"`             //管理员ID
	AgentID       bson.ObjectID `json:"AgentID" bson:"AgentID"`             //代理ID
	DeviceID      string             `json:"DeviceID" bson:"DeviceID"`           //设备ID
	DkCount       int64              `json:"DkCount" bson:"DkCount"`             //多开数量设定0=无限多开 默认为3 最大为100
	ExeID         bson.ObjectID `json:"ExeID" bson:"ExeID"`                 //绑定的软件
	Name          string             `json:"Name" bson:"Name"`                   //用户名
	Pwd           string             `json:"Pwd" bson:"Pwd"`                     //密码
	Level         int64              `json:"Level" bson:"Level"`                 //用户等级 0=小时卡 1=天卡 2=周卡 3=月卡 4=季卡 5=半年卡 6=年卡 7=永久卡
	Serial        string             `json:"Serial" bson:"Serial"`               //最后一次充值的卡号
	State         bool               `json:"State" bson:"State"`                 //状态
	Online        bool               `json:"Online" bson:"Online"`               //在线状态
	RegIP         string             `json:"RegIP" bson:"RegIP"`                 //注册ip
	RegTime       time.Time          `json:"RegTime" bson:"RegTime"`             //注册时间
	EndTime       time.Time          `json:"EndTime" bson:"EndTime"`             //到期时间
	LoginIP       string             `json:"LoginIP" bson:"LoginIP"`             //登录ip
	LastLoginIP   string             `json:"LastLoginIP" bson:"LastLoginIP"`     //上一次登录ip
	LoginTime     time.Time          `json:"LoginTime" bson:"LoginTime"`         //登录时间
	LastLoginTime time.Time          `json:"LastLoginTime" bson:"LastLoginTime"` //上一次登录时间
	Bak           string             `json:"Bak" bson:"Bak"`                     //备注
	BindCont      int64              `json:"BindCont" bson:"BindCont"`           //当前用户换绑次数
	BindTime      time.Time          `json:"BindTime" bson:"BindTime"`           //换绑的时间
	Conf          string             `json:"Conf" bson:"Conf"`                   //用户配置信息
}

// PayLink 支付连接
type PayLink struct {
	PayLink     string `json:"payLink"`     //微信连接
	PayCarLink  string `json:"PayCarLink"`  //发卡连接
	PayAliState bool   `json:"PayAliState"` //支付宝当面付是否启用
}

type resDate struct {
	Tag             string  `json:"Tag"`
	Msg             string  `json:"Msg"`
	Code            int     `json:"Code"`              //标识
	Yzm             string  `json:"yzm"`               //验证码
	Base64Code      string  `json:"base64Code"`        //支付二维码
	CompletePayment bool    `json:"isCompletePayment"` //是否完成支付
	Variable        string  `json:"variable"`
	Car             Car     `json:"car"`
	PayLink         PayLink `json:"payLink"`
}

// tagCode 验证码
const tagDevKey = "DevKey"
const tagCode = "GetCode"
const tagExe = "GetExeInfo"
const tagRegister = "Register"
const tagLogin = "Login"
const tagCarLogin = "CarLogin"
const tagUserPay = "UserPay"
const tagUpUserPwd = "UpUserPwd"
const tagBindDeviceID = "BindDeviceID"
const tagAddBlack = "AddBlack"
const tagUserInfo = "GetUserInfo"
const tagSetUerConf = "SetUerConf"
const tagExeData = "GetExeData"
const tagVariable = "GetVariable"
const tagAdminPay = "GetAdminPay"
const tagCar = "FindCarInfo"
const tagAliPayCreate = "AliPayCreate"
const tagCompletePayment = "isCompletePayment"
const tagPing = "Ping"
const tagQuick = "QuickLogin"
const tagVMPAuth = "VMPAuth"
const tagCkLogin = "CKLogin"
