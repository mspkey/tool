package main

import (
	"errors"
	"fmt"
	"gitee.com/mspkey/tool/sdk"
	"log"
)

func main() {
	ms := sdk.MspKey{}
	DevID := sdk.GetDevID()
	err := ms.Init("msplock.vip:8810", "6596a0f241717f66bb0457d1", DevID, "646e0cdba20867821d3cc050")
	if err != nil {
		log.Fatalln(err)
	}

	err = ms.QuickLogin()
	if err != nil {
		log.Fatalln(err)
	}

	if !ms.IsLogin() {
		log.Fatalln(errors.New("尚未登录"))
	}

	err = ms.GetUserInfo()
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(fmt.Sprintf("到期时间为:%s", ms.Info.EndTime))
}

// test 测试例子
func test() {

	ms := sdk.MspKey{}
	ms.IsDug = true
	DevID := sdk.GetDevID()
	err := ms.Init("msplock.vip:8810", "6596a0f241717f66bb0457d1", DevID, "646e0cdba20867821d3cc050")
	if err != nil {
		log.Fatalln(err)
	}

	err = ms.QuickLogin()
	if err != nil {
		log.Fatalln(err)
	}

	if !ms.IsLogin() {
		log.Fatalln(errors.New("尚未登录"))
	}

	err = ms.GetUserInfo()
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(fmt.Sprintf("到期时间为:%s", ms.Info.EndTime.Location()))
	//请初始化你的远程变量

	//获取软件信息
	//_ = ms.GetExeInfo()123
	//log.Println(ms.Exe.Title)

	//获取验证码
	//code, _ := ms.GetCode()
	//log.Println(code)

	//用户注册
	//err = ms.Register("test123", "110110", "2TTH")
	//if err != nil {
	//	log.Println(err)
	//}

	//用户登录
	//err = ms.Login("test123", "110110")
	//if err != nil {
	//	log.Println(err)
	//}

	//卡密登录
	//err = ms.CarLogin("19543b43-8768-43b3-a488-9cf5e1187700")
	//if err != nil {
	//	log.Println(err)
	//}

	//账号充值
	//err = ms.UserPay("test123", "53a3332d-add7-4330-b24b-01fade7c2568")
	//if err != nil {
	//	log.Println(err)
	//}

	//换绑操作
	//err = ms.BindDeviceID("test123", "110110")
	//if err != nil {
	//	log.Println(err)
	//}

	//更新密码
	//err = ms.UpUserPwd("test123", "110110", "123456")
	//if err != nil {
	//	log.Println(err)
	//}

	//获取用户信息
	//err = ms.GetUserInfo()
	//if err == nil {
	//	log.Println(ms.Info.Name)
	//}

	//设置用户云配置
	//err = ms.SetUerConf("你好世界")
	//if err != nil {
	//	log.Println(err)
	//}

	//获取核心数据
	//data,err := ms.GetExeData()
	//if err == nil {
	//	log.Println(data)
	//}

	//获取远程变量
	//variable, err := ms.GetVariable("1111")
	//if err == nil {
	//	log.Println(variable)
	//}

	//获取发卡连接
	//pay, err := ms.GetAdminPay()
	//if err == nil {
	//	log.Println(pay)
	//}

}
