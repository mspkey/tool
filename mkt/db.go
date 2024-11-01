package mkt

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

// 软件
type Exe struct {
	ID         primitive.ObjectID `json:"ID" bson:"_id"`                 //软件ID
	AdminID    primitive.ObjectID `json:"AdminID"  bson:"AdminID"`       //绑定管理员ID
	Title      string             `json:"Title"  bson:"Title"`           //软件标题
	Versions   string             `json:"Versions"  bson:"Versions"`     //版本
	State      bool               `json:"State"  bson:"State"`           //状态 正常/禁用
	Notice     string             `json:"Notice"  bson:"Notice"`         //公告
	Address    string             `json:"Address"  bson:"Address"`       //更新地址
	Md5        string             `json:"Md5"  bson:"Md5"`               //软件MD5
	Data       string             `json:"Data"  bson:"Data"`             //软件核心数据
	Key        string             `json:"Key"  bson:"Key"`               //密钥
	IsDK       bool               `json:"IsDK"  bson:"IsDK"`             //是否多开
	IsReg      bool               `json:"IsReg"  bson:"IsReg"`           //是否允许注册
	IsDbg      bool               `json:"IsDbg"  bson:"IsDbg"`           //是否开启检测
	IsBindIP   bool               `json:"IsBindIP"  bson:"IsBindIP"`     //是否绑定IP
	IsDeviceID bool               `json:"IsDeviceID"  bson:"IsDeviceID"` //绑定设备ID
	GiveTime   int64              `json:"GiveTime"  bson:"GiveTime"`     //软件注册赠送时间 分钟
	BindCount  int64              `json:"BindCount"  bson:"BindCount"`   //设置换绑次数
}

// 用户
type User struct {
	ID        primitive.ObjectID `bson:"_id"`       //用户ID
	AdminID   primitive.ObjectID `bson:"AdminID"`   //管理员ID
	DeviceID  string             `bson:"DeviceID"`  //设备ID
	ExeID     primitive.ObjectID `bson:"ExeID"`     //绑定的软件
	Name      string             `bson:"Name"`      //用户名
	Pwd       string             `bson:"Pwd"`       //密码
	Serial    string             `bson:"Serial"`    //最后一次充值的卡号
	State     bool               `bson:"State"`     //状态
	RegIP     string             `bson:"RegIP"`     //注册ip
	RegTime   time.Time          `bson:"RegTime"`   //注册时间
	EndTime   time.Time          `bson:"EndTime"`   //到期时间
	LoginTime time.Time          `bson:"LoginTime"` //登录时间
	Bak       string             `bson:"Bak"`       //备注
	Sig       string             `bson:"Sig"`       //登录码
	BindCont  int64              `bson:"BindCont"`  //当前用户换绑次数
	BindTime  time.Time          `bson:"BindTime"`  //换绑的时间
}

// 验证码
type Code struct {
	IP     string    `bson:"IP"`
	Count  int       `bson:"LoginCount"` //技术
	Code   string    `bson:"Code"`       //验证码`
	DBTime time.Time `bson:"DBTime"`     //到期时间
}
