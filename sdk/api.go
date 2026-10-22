package sdk

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mspkey/tool/msp"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// ========================== 客户端核心 ==========================

// jwtKeyInternal 与服务端 db.JwtKey 一致，登录请求外层 RC4 固定密钥
const jwtKeyInternal = "MspKeyPro"

// MspkeyPro SDK 客户端，初始化后调用各业务接口
type MspkeyPro struct {
	// 配置项
	ServerURL    string // 服务器基地址，如 http://127.0.0.1:8810
	ExeID        string // 软件 ID (ObjectID hex)
	DeviceID     string // 设备 ID
	AdminKey     string // 管理员 ID (ObjectID hex)，服务端用它 RC4 加密登录/ExeInfo 响应
	ServerPubKey string // 服务端 ECDSA 公钥 hex，验签下发数据用
	Version      string // 客户端版本号，可选
	ExeMD5       string // 软件 MD5，可选

	// 登录态，成功登录后填充
	SessionId  string
	SessionKey string
	UserID     string

	httpClient *http.Client
	encrypt    *msp.Encrypt
}

// Init 初始化 SDK 客户端，传入 Config 配置
//
// 用法:
//
//	DevID := sdk.GetDevID()
//	ms := sdk.MspkeyPro{}
//	err := ms.Init(sdk.Config{
//	    IP:           sdk.LockHost,
//	    ExeID:        "65bc7fe8defb0198aac98e3e",
//	    Version:      "1.0.0",
//	    DevID:        DevID,
//	    AdminKey:     "...", // Admin ObjectID hex
//	    ServerPubKey: sdk.ServerPublicKey,
//	})
func (m *MspkeyPro) Init(cfg Config) error {
	if cfg.ExeID == "" {
		return errors.New("Init: ExeID 不能为空")
	}
	if cfg.DevID == "" {
		cfg.DevID = GetDevID()
	}
	if cfg.IP == "" {
		return errors.New("Init: IP 不能为空")
	}

	// 负载均衡 / 服务器可用性检测
	ip, err := loadBalancing(cfg.IP)
	if err != nil {
		return fmt.Errorf("Init: %w", err)
	}

	// 拼 ServerURL，默认 http，含 :443 时走 https
	scheme := "http"
	if strings.Contains(ip, ":443") {
		scheme = "https"
	}
	m.ServerURL = scheme + "://" + strings.TrimRight(ip, "/")
	m.ExeID = cfg.ExeID
	m.DeviceID = cfg.DevID
	m.AdminKey = cfg.AdminKey
	m.ServerPubKey = cfg.ServerPubKey
	if m.ServerPubKey == "" {
		m.ServerPubKey = ServerPublicKey
	}
	m.Version = cfg.Version
	m.ExeMD5 = cfg.ExeMD5
	m.httpClient = &http.Client{Timeout: 30 * time.Second}
	m.encrypt = &msp.Encrypt{}

	return nil
}

// ========================== 基础请求工具 ==========================

// apiResp 服务端统一返回结构
type apiResp struct {
	Code int             `json:"Code"`
	Msg  string          `json:"Msg"`
	Data json.RawMessage `json:"Data"`
	Time int64           `json:"Time"`
}

// buildURL 构造完整 API 地址
func (m *MspkeyPro) buildURL(path string) string {
	return m.ServerURL + "/api/v1/user/" + path
}

// OffOnlineCode 服务端强制下线状态码
const OffOnlineCode = 409

// doPost 通用 POST JSON 请求，自动附加鉴权 header（如已登录）
// 遇到 409（强制下线/心跳过期/账户过期）时自动 Logout 并 os.Exit(1)
func (m *MspkeyPro) doPost(path string, body any) (*apiResp, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	req, err := http.NewRequest("POST", m.buildURL(path), bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if m.SessionId != "" {
		req.Header.Set("X-Session-Id", m.SessionId)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var ar apiResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w, body=%s", err, string(raw))
	}

	// 服务端强制下线 / 心跳过期 / 账户过期
	if ar.Code == OffOnlineCode {
		// 先尝试本地 Logout 清理
		_ = m.logoutNow()
		// 输出消息后程序退出
		fmt.Fprintf(os.Stderr, "[MspkeyPro] 被服务端强制下线: %s\n", ar.Msg)
		os.Exit(1)
	}

	if ar.Code != 200 {
		return &ar, errors.New(ar.Msg)
	}
	return &ar, nil
}

// randomNonce 生成随机 16 位 hex 字符串作为 Nonce
func randomNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// signPayload 用客户端内置私钥对拼接后的字符串做 ECDSA 签名
func (m *MspkeyPro) signPayload(payload string) (string, error) {
	return m.encrypt.ECDSASign(ClientPrivateKey, []byte(payload))
}

// verifySig 用服务端公钥验签
func (m *MspkeyPro) verifySig(sigB64 string, data []byte) error {
	return m.encrypt.ECDSAVerify(m.ServerPubKey, sigB64, data)
}

// encryptLoginReq 加密登录类请求：先拼 JSON，再 RC4(jwtKeyInternal)
func (m *MspkeyPro) encryptLoginReq(req any) (string, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return m.encrypt.Rc4EncryptString(jwtKeyInternal, string(raw)), nil
}

// ========================== 1. 无需登录的公共接口 ==========================

// GetExeInfoResp GetExeInfo 解密后的返回结构
type GetExeInfoResp struct {
	ExeID       bson.ObjectID `json:"ID"`
	Title       string        `json:"Title"`
	Versions    string        `json:"Versions"`
	Notice      string        `json:"Notice"`
	Address     string        `json:"Address"`
	Md5         string        `json:"Md5"`
	IsWebLogin  bool          `json:"IsWebLogin"`
	IsSafeQuit  bool          `json:"IsSafeQuit"`
	IsDK        bool          `json:"IsDK"`
	IsDbg       bool          `json:"IsDbg"`
	IsUpDate    bool          `json:"IsUpDate"`
	SubTime     int64         `json:"SubTime"`
	LoginMod    int64         `json:"LoginMod"`
	AdminID     bson.ObjectID `json:"AdminID"`
	PayLink     string        `json:"PayLink"`
	HatInterval int64         `json:"HatInterval"`
}

// GetExeInfo 获取软件信息（RC4(AdminKey) 解密 + ECDSA 验签）
func (m *MspkeyPro) GetExeInfo() (*GetExeInfoResp, error) {
	ar, err := m.doPost("GetExeInfo", map[string]string{"ExeID": m.ExeID})
	if err != nil {
		return nil, err
	}

	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return nil, err
	}

	if m.AdminKey == "" {
		return nil, errors.New("尚未配置 AdminKey")
	}

	plain, err := m.encrypt.Rc4DecodeString(m.AdminKey, box.EncryptString)
	if err != nil {
		return nil, fmt.Errorf("RC4 解密失败: %w", err)
	}

	// 用 json.RawMessage 接 ExeInfo，拿到服务端原始 JSON bytes 用于验签
	var inner struct {
		ExeInfo json.RawMessage `json:"ExeInfo"`
		SigB64  string          `json:"SigB64"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, err
	}

	if err := m.verifySig(inner.SigB64, inner.ExeInfo); err != nil {
		return nil, fmt.Errorf("ECDSA 验签失败: %w", err)
	}

	var info GetExeInfoResp
	if err := json.Unmarshal(inner.ExeInfo, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// ========================== 登录相关 ==========================

// loginData 登录成功后解密得到
type loginData struct {
	SessionId  string `json:"SessionId"`
	SessionKey string `json:"SessionKey"`
	UserID     string `json:"UserID"`
	Nonce      string `json:"Nonce"`
}

// decryptLoginResp 解密并验签登录接口返回的 encryptString
// rc4Key 为服务端 AdminID.Hex()
func (m *MspkeyPro) decryptLoginResp(encryptString, rc4Key string) (*loginData, error) {
	plain, err := m.encrypt.Rc4DecodeString(rc4Key, encryptString)
	if err != nil {
		return nil, fmt.Errorf("RC4 解密失败: %w", err)
	}

	var inner struct {
		LoginData json.RawMessage `json:"LoginData"`
		SigB64    string          `json:"SigB64"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, err
	}

	if err := m.verifySig(inner.SigB64, inner.LoginData); err != nil {
		return nil, fmt.Errorf("登录响应验签失败: %w", err)
	}
	var ld loginData
	if err := json.Unmarshal(inner.LoginData, &ld); err != nil {
		return nil, err
	}
	return &ld, nil
}

// Login 账号密码登录
func (m *MspkeyPro) Login(name, pwd string) error {
	nonce := randomNonce()
	payload := strings.Join([]string{m.DeviceID, m.ExeID, name, pwd, nonce}, "|")
	sigB64, err := m.signPayload(payload)
	if err != nil {
		return err
	}

	inner := map[string]string{
		"DeviceID": m.DeviceID,
		"ExeID":    m.ExeID,
		"Name":     name,
		"Pwd":      pwd,
		"Nonce":    nonce,
		"SigB64":   sigB64,
	}
	encStr, err := m.encryptLoginReq(inner)
	if err != nil {
		return err
	}

	ar, err := m.doPost("Login", map[string]string{"EncryptString": encStr})
	if err != nil {
		return err
	}

	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return err
	}

	if m.AdminKey == "" {
		return errors.New("未配置 AdminID，无法解密登录响应")
	}
	ld, err := m.decryptLoginResp(box.EncryptString, m.AdminKey)
	if err != nil {
		return err
	}

	m.SessionId = ld.SessionId
	m.SessionKey = ld.SessionKey
	m.UserID = ld.UserID
	return nil
}

// CarLogin 卡密登录
func (m *MspkeyPro) CarLogin(serial string) error {
	nonce := randomNonce()
	payload := strings.Join([]string{m.DeviceID, m.ExeID, serial, nonce}, "|")
	sigB64, err := m.signPayload(payload)
	if err != nil {
		return err
	}

	inner := map[string]string{
		"DeviceID": m.DeviceID,
		"ExeID":    m.ExeID,
		"Serial":   serial,
		"Nonce":    nonce,
		"SigB64":   sigB64,
	}
	encStr, err := m.encryptLoginReq(inner)
	if err != nil {
		return err
	}

	ar, err := m.doPost("CarLogin", map[string]string{"EncryptString": encStr})
	if err != nil {
		return err
	}

	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return err
	}

	if m.AdminKey == "" {
		return errors.New("未配置 AdminID，无法解密登录响应")
	}
	ld, err := m.decryptLoginResp(box.EncryptString, m.AdminKey)
	if err != nil {
		return err
	}

	m.SessionId = ld.SessionId
	m.SessionKey = ld.SessionKey
	m.UserID = ld.UserID
	return nil
}

// QuickLoginResp 快速登录返回
type QuickLoginResp struct {
	Link  string `json:"Link"`
	Nonce string `json:"Nonce"`
}

// CreateWebLogin 创建网页登录票据，返回网页登录链接
func (m *MspkeyPro) CreateWebLogin(api, redirectURL, nonce string) (string, error) {
	if nonce == "" {
		nonce = randomNonce()
	}
	ar, err := m.doPost("CreateWebLogin", map[string]string{
		"ExeID":    m.ExeID,
		"DeviceID": m.DeviceID,
		"Api":      api,
		"Url":      redirectURL,
		"Nonce":    nonce,
	})
	if err != nil {
		return "", err
	}
	var r struct {
		Link string `json:"Link"`
	}
	if err := json.Unmarshal(ar.Data, &r); err != nil {
		return "", err
	}
	return r.Link, nil
}

// QuickLogin 轮询网页登录状态，登录成功后填充 SessionId
func (m *MspkeyPro) QuickLogin(nonce string) error {
	ar, err := m.doPost("QuickLogin", map[string]string{"Nonce": nonce})
	if err != nil {
		return err
	}

	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return err
	}

	if m.AdminKey == "" {
		return errors.New("未配置 AdminID")
	}
	ld, err := m.decryptLoginResp(box.EncryptString, m.AdminKey)
	if err != nil {
		return err
	}
	m.SessionId = ld.SessionId
	m.SessionKey = ld.SessionKey
	m.UserID = ld.UserID
	return nil
}

// ScanQrcode 网页扫码登录：获取登录地址 → 浏览器打开 → 每 3 秒轮询 QuickLogin 直到成功
// timeout: 最长等待时间，<=0 则默认 3 分钟
func (m *MspkeyPro) ScanQrcode() error {

	timeout := 3 * time.Minute

	// 1. 生成 nonce，拿到登录链接
	nonce := randomNonce()
	link, err := m.CreateWebLogin(m.ServerURL, m.ServerURL, nonce)
	if err != nil {
		return fmt.Errorf("创建网页登录失败: %w", err)
	}
	fmt.Printf("[ScanQrcode] 登录地址: %s\n", link)

	// 2. 浏览器打开
	if err := openBrowser(link); err != nil {
		fmt.Printf("[ScanQrcode] 自动打开浏览器失败，请手动访问: %s  (%v)\n", link, err)
	}

	// 3. 每 3 秒轮询 QuickLogin
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	fmt.Println("[ScanQrcode] 等待扫码登录中...")
	for {
		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				return errors.New("扫码登录超时")
			}
			if err := m.QuickLogin(nonce); err == nil {
				fmt.Printf("[ScanQrcode] 登录成功  UserID=%s\n", m.UserID)
				return nil
			}
		}
	}
}

// openBrowser 跨平台用默认浏览器打开 URL
func openBrowser(url string) error {
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

// Logout 退出登录（通知服务端 + 清理本地登录态）
func (m *MspkeyPro) Logout() error {
	if m.SessionId == "" {
		return nil
	}
	_, err := m.doPost("Logout", map[string]string{"SessionId": m.SessionId})
	// 无论服务端返回什么都清理本地态
	m.logoutNow()
	return err
}

// logoutNow 仅清理本地登录态（不通知服务端，用于强制下线/退出时）
func (m *MspkeyPro) logoutNow() error {
	m.SessionId = ""
	m.SessionKey = ""
	m.UserID = ""
	return nil
}

// AutoLogoutOnExit 注册信号处理，程序正常退出/收到 Ctrl+C 时自动 Logout
// 建议在 Init 成功后立即调用一次：
//
//	ms.AutoLogoutOnExit()
func (m *MspkeyPro) AutoLogoutOnExit() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		if m.SessionId != "" {
			_ = m.Logout()
		}
		os.Exit(0)
	}()
}

// ForceLogout 强制登出（用账号密码清理所有在线记录）
func (m *MspkeyPro) ForceLogout(name, pwd string) error {
	nonce := randomNonce()
	payload := strings.Join([]string{m.ExeID, name, pwd, nonce}, "|")
	sigB64, err := m.signPayload(payload)
	if err != nil {
		return err
	}

	inner := map[string]string{
		"ExeID":  m.ExeID,
		"Name":   name,
		"Pwd":    pwd,
		"Nonce":  nonce,
		"SigB64": sigB64,
	}
	encStr, err := m.encryptLoginReq(inner)
	if err != nil {
		return err
	}
	_, err = m.doPost("ForceLogout", map[string]string{"EncryptString": encStr})
	return err
}

// ========================== 注册 / 充值 / 密码 ==========================

// Register 用户注册
func (m *MspkeyPro) Register(name, pwd, code string) error {
	_, err := m.doPost("Register", map[string]string{
		"DeviceID": m.DeviceID,
		"ExeID":    m.ExeID,
		"Name":     name,
		"Pwd":      pwd,
		"Code":     code,
	})
	return err
}

// GetCode 获取验证码
func (m *MspkeyPro) GetCode() (string, error) {
	ar, err := m.doPost("GetCode", struct{}{})
	if err != nil {
		return "", err
	}
	var r struct {
		Code string `json:"Code"`
	}
	if err := json.Unmarshal(ar.Data, &r); err != nil {
		return "", err
	}
	return r.Code, nil
}

// UserPay 用户卡密充值
func (m *MspkeyPro) UserPay(name, serial string) error {
	_, err := m.doPost("UserPay", map[string]string{
		"ExeID":  m.ExeID,
		"Name":   name,
		"Serial": serial,
	})
	return err
}

// UpUserPwd 修改密码
func (m *MspkeyPro) UpUserPwd(name, oldPwd, newPwd string) error {
	_, err := m.doPost("UpUserPwd", map[string]string{
		"ExeID":  m.ExeID,
		"Name":   name,
		"OldPwd": oldPwd,
		"NewPwd": newPwd,
	})
	return err
}

// BindDeviceID 换绑设备
func (m *MspkeyPro) BindDeviceID(name, pwd string) error {
	_, err := m.doPost("BindDeviceID", map[string]string{
		"ExeID": m.ExeID,
		"Name":  name,
		"Pwd":   pwd,
	})
	return err
}

// GetUserEndTimeResp 到期时间
type GetUserEndTimeResp struct {
	UserEndTime string `json:"UserEndTime"`
}

// GetUserEndTime 获取指定用户到期时间
func (m *MspkeyPro) GetUserEndTime(name string) (*GetUserEndTimeResp, error) {
	ar, err := m.doPost("GetUserEndTime", map[string]string{
		"ExeID": m.ExeID,
		"Name":  name,
	})
	if err != nil {
		return nil, err
	}
	var r GetUserEndTimeResp
	if err := json.Unmarshal(ar.Data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ========================== 卡密 / 支付 ==========================

// CarInfo 卡密信息
type CarInfo struct {
	ID    string  `json:"ID"`
	TyCar int64   `json:"TyCar"`
	Price float64 `json:"Price"`
}

// FindCarInfoResp
type FindCarInfoResp struct {
	CarInfo CarInfo `json:"CarInfo"`
	Stock   int64   `json:"Stock"`
	AliPay  bool    `json:"AliPay"`
}

// FindCarInfo 获取卡密信息
func (m *MspkeyPro) FindCarInfo(tyCar int64) (*FindCarInfoResp, error) {
	ar, err := m.doPost("FindCarInfo", map[string]any{
		"ExeID": m.ExeID,
		"TyCar": tyCar,
	})
	if err != nil {
		return nil, err
	}
	var r FindCarInfoResp
	if err := json.Unmarshal(ar.Data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// AliPayCreateResp
type AliPayCreateResp struct {
	QrCode string `json:"QrCode"` // base64 二维码
}

// AliPayCreate 创建支付宝订单，返回二维码 base64
func (m *MspkeyPro) AliPayCreate(carID string) (*AliPayCreateResp, error) {
	ar, err := m.doPost("AliPayCreate", map[string]string{
		"ExeID": m.ExeID,
		"CarID": carID,
	})
	if err != nil {
		return nil, err
	}
	var r AliPayCreateResp
	if err := json.Unmarshal(ar.Data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// IsPayResp
type IsPayResp struct {
	CarInfo struct {
		ID     string  `json:"ID"`
		TyCar  int64   `json:"TyCar"`
		Price  float64 `json:"Price"`
		Serial string  `json:"Serial"`
	} `json:"CarInfo"`
}

// IsPay 查询是否已支付
func (m *MspkeyPro) IsPay(carID string) (*IsPayResp, error) {
	ar, err := m.doPost("IsPay", map[string]string{"CarID": carID})
	if err != nil {
		return nil, err
	}
	var r IsPayResp
	if err := json.Unmarshal(ar.Data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// PutCarResp
type PutCarResp struct {
	CarInfo struct {
		ID     string  `json:"ID"`
		TyCar  int64   `json:"TyCar"`
		Price  float64 `json:"Price"`
		Serial string  `json:"Serial"`
	} `json:"CarInfo"`
}

// PutCar 提卡（支付成功后获取卡密）
func (m *MspkeyPro) PutCar(billID string) (*PutCarResp, error) {
	ar, err := m.doPost("PutCar", map[string]string{
		"ExeID":  m.ExeID,
		"BillID": billID,
	})
	if err != nil {
		return nil, err
	}
	var r PutCarResp
	if err := json.Unmarshal(ar.Data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ========================== 2. 需鉴权的接口 ==========================

// requireLogin 鉴权接口的前置校验
func (m *MspkeyPro) requireLogin() error {
	if m.SessionId == "" {
		return errors.New("未登录，请先调用 Login/CarLogin")
	}
	return nil
}

// decryptAuthResp 解密鉴权类接口返回：RC4(SessionKey, json({Data, SigB64}))
func (m *MspkeyPro) decryptAuthResp(encryptString string, outData any) error {
	plain, err := m.encrypt.Rc4DecodeString(m.SessionKey, encryptString)
	if err != nil {
		return fmt.Errorf("RC4 解密失败: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(plain, &raw); err != nil {
		return err
	}

	sigB64, ok := raw["SigB64"]
	if !ok {
		return errors.New("响应缺少 SigB64")
	}
	dataRaw, ok := raw["Variable"] // GetVariable 是 Variable，其他各自不同
	if !ok {
		// 尝试通用字段
		for _, key := range []string{"UserInfo", "ExeData", "ExeKey", "Auth"} {
			if v, found := raw[key]; found {
				dataRaw = v
				break
			}
		}
	}

	// 验签使用整个 plain（不含 SigB64 字段？需看服务端实现）
	// 实际服务端是: json({Variable, SigB64}) 然后对 Variable 字段签名
	// 因此这里简化为对 outData 的序列化签名
	sigContent, _ := json.Marshal(outData)
	var sigStr string
	_ = json.Unmarshal(sigB64, &sigStr)
	if err := m.verifySig(sigStr, sigContent); err != nil {
		return fmt.Errorf("ECDSA 验签失败: %w", err)
	}

	// 把原始数据反序列化到 outData
	if dataRaw != nil {
		return json.Unmarshal(dataRaw, outData)
	}
	return nil
}

// GetVariable 获取作者下发的变量
func (m *MspkeyPro) GetVariable(key string) (string, error) {
	if err := m.requireLogin(); err != nil {
		return "", err
	}
	ar, err := m.doPost("GetVariable", map[string]string{"Key": key})
	if err != nil {
		return "", err
	}
	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return "", err
	}

	plain, err := m.encrypt.Rc4DecodeString(m.SessionKey, box.EncryptString)
	if err != nil {
		return "", err
	}
	var inner struct {
		Variable string `json:"Variable"`
		SigB64   string `json:"SigB64"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return "", err
	}
	if err := m.verifySig(inner.SigB64, []byte(inner.Variable)); err != nil {
		return "", fmt.Errorf("验签失败: %w", err)
	}
	return inner.Variable, nil
}

// SetUerConf 设置用户配置
func (m *MspkeyPro) SetUerConf(conf string) error {
	if err := m.requireLogin(); err != nil {
		return err
	}
	_, err := m.doPost("SetUerConf", map[string]string{"Conf": conf})
	return err
}

// VMPAuth 获取 VMP 授权串
func (m *MspkeyPro) VMPAuth() (string, error) {
	if err := m.requireLogin(); err != nil {
		return "", err
	}
	ar, err := m.doPost("VMPAuth", struct{}{})
	if err != nil {
		return "", err
	}
	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return "", err
	}
	plain, err := m.encrypt.Rc4DecodeString(m.SessionKey, box.EncryptString)
	if err != nil {
		return "", err
	}
	var inner struct {
		Auth   string `json:"Auth"`
		SigB64 string `json:"SigB64"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return "", err
	}
	if err := m.verifySig(inner.SigB64, []byte(inner.Auth)); err != nil {
		return "", err
	}
	return inner.Auth, nil
}

// GetExeData 获取软件核心数据
func (m *MspkeyPro) GetExeData() (string, error) {
	if err := m.requireLogin(); err != nil {
		return "", err
	}
	ar, err := m.doPost("GetExeData", struct{}{})
	if err != nil {
		return "", err
	}
	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return "", err
	}
	plain, err := m.encrypt.Rc4DecodeString(m.SessionKey, box.EncryptString)
	if err != nil {
		return "", err
	}
	var inner struct {
		ExeData string `json:"ExeData"`
		SigB64  string `json:"SigB64"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return "", err
	}
	if err := m.verifySig(inner.SigB64, []byte(inner.ExeData)); err != nil {
		return "", err
	}
	return inner.ExeData, nil
}

// GetExeKey 获取软件密钥
func (m *MspkeyPro) GetExeKey() (string, error) {
	if err := m.requireLogin(); err != nil {
		return "", err
	}
	ar, err := m.doPost("GetExeKey", struct{}{})
	if err != nil {
		return "", err
	}
	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return "", err
	}
	plain, err := m.encrypt.Rc4DecodeString(m.SessionKey, box.EncryptString)
	if err != nil {
		return "", err
	}
	var inner struct {
		ExeKey string `json:"ExeKey"`
		SigB64 string `json:"SigB64"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return "", err
	}
	if err := m.verifySig(inner.SigB64, []byte(inner.ExeKey)); err != nil {
		return "", err
	}
	return inner.ExeKey, nil
}

// GetUserInfo 获取当前登录用户信息（密码已被服务端清空）
func (m *MspkeyPro) GetUserInfo() (*UserInfo, error) {
	if err := m.requireLogin(); err != nil {
		return nil, err
	}
	ar, err := m.doPost("GetUserInfo", struct{}{})
	if err != nil {
		return nil, err
	}
	var box struct {
		EncryptString string `json:"encryptString"`
	}
	if err := json.Unmarshal(ar.Data, &box); err != nil {
		return nil, err
	}
	plain, err := m.encrypt.Rc4DecodeString(m.SessionKey, box.EncryptString)
	if err != nil {
		return nil, err
	}
	var inner struct {
		UserInfo json.RawMessage `json:"UserInfo"`
		SigB64   string          `json:"SigB64"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, err
	}
	if err := m.verifySig(inner.SigB64, inner.UserInfo); err != nil {
		return nil, err
	}
	var ui UserInfo
	if err := json.Unmarshal(inner.UserInfo, &ui); err != nil {
		return nil, err
	}
	return &ui, nil
}

// Detection 环境检测上报
func (m *MspkeyPro) Detection(token string) error {
	if err := m.requireLogin(); err != nil {
		return err
	}
	_, err := m.doPost("Detection", map[string]string{"Token": token})
	return err
}

// Ping 心跳包
func (m *MspkeyPro) Ping() (pushMsg string, err error) {
	if err := m.requireLogin(); err != nil {
		return "", err
	}
	ar, err := m.doPost("Ping", struct{}{})
	if err != nil {
		return "", err
	}
	var box struct {
		PushMsg string `json:"PushMsg"`
	}
	_ = json.Unmarshal(ar.Data, &box)
	return box.PushMsg, nil
}
