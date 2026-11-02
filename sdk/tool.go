package sdk

import (
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mspkey/tool/msp"
)

// GetDevID 获取设备ID
func GetDevID() string {
	id := msp.DeviceID{}
	address := id.GetMac()
	e := msp.Encrypt{}
	return e.Md5Encrypt(address[0])
}

// pingServer 检测服务器是否可用
// 服务端路由: POST /api/v1/Ping → {"Msg":"服务可用OK", "Time":...}
func pingServer(IP string) error {
	scheme := "http"
	if strings.Contains(IP, ":443") {
		scheme = "https"
	}
	URL := scheme + "://" + IP + "/api/v1/Ping"

	resp, err := http.Post(URL, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if strings.Contains(string(body), "服务可用OK") {
		return nil
	}
	return errors.New("服务器连接不可用")
}

const (
	// iplistCacheDir 本地缓存目录名（与 Python SDK 一致）
	iplistCacheDir = ".MspTool"
	// iplistCacheFile 本地服务器列表缓存文件名
	iplistCacheFile = "ServerList.dat"
	// iplistRefreshInterval 本地服务器列表与服务端的校验周期
	iplistRefreshInterval = 72 * time.Hour
	// iplistRc4Key 服务端 GetIplist 下发数据的 RC4 密钥，与 db.BaseKey 一致
	iplistRc4Key = "MspKeyPro"
	// iplistCacheSalt 本地缓存密钥派生盐，与 Python SDK 一致
	iplistCacheSalt = "::SrvLst::Cache::v1"
)

// defaultIplist 服务端未配置列表时使用的兜底地址
var defaultIplist = []string{"pro.msplock.vip:443", "pro.msplock.vip:8820"}

// iplistCache 本地服务器列表缓存
type iplistCache struct {
	Iplist     []string `json:"Iplist"`     // 服务器地址列表
	SigB64     string   `json:"SigB64"`     // 服务端对 Iplist + UpdateTime 的 ECDSA 签名，防止本地缓存被篡改
	UpdateTime int64    `json:"UpdateTime"` // 上次与服务端同步(或校验)的时间，Unix 秒
}

// iplistSigPayload 签名原文：ip1|ip2|...|UpdateTime（与服务端 strings.Join(Iplist,"|") + "|" + Unix秒 一致）
func iplistSigPayload(list []string, updateTime int64) []byte {
	return []byte(strings.Join(list, "|") + "|" + strconv.FormatInt(updateTime, 10))
}

// verifyIplistSig 验签：用服务端公钥校验 Iplist + UpdateTime 未被篡改
func verifyIplistSig(list []string, updateTime int64, sigB64 string) error {
	return (&msp.Encrypt{}).ECDSAVerify(ServerPublicKey, sigB64, iplistSigPayload(list, updateTime))
}

// fetchIplist 从服务器拉取服务器列表（RC4 解密 + ECDSA 验签）
// 服务端路由: POST /api/v1/user/GetIplist → {"encryptString":"..."}
// 解密后: {"Iplist":[...], "SigB64":"...", "UpdateTime": Unix秒}
// 返回的缓存数据可直接写入本地，签名一起缓存以防篡改
func fetchIplist(IP string) (*iplistCache, error) {
	scheme := "http"
	if strings.Contains(IP, ":443") {
		scheme = "https"
	}
	URL := scheme + "://" + IP + "/api/v1/user/GetIplist"

	resp, err := http.Post(URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ar struct {
		Code int    `json:"Code"`
		Msg  string `json:"Msg"`
		Data struct {
			EncryptString string `json:"encryptString"`
		} `json:"Data"`
	}
	if err = json.Unmarshal(body, &ar); err != nil {
		return nil, err
	}
	if ar.Code != 200 {
		if ar.Msg == "" {
			ar.Msg = "获取服务器列表失败"
		}
		return nil, errors.New(ar.Msg)
	}

	plain, err := (&msp.Encrypt{}).Rc4DecodeString(iplistRc4Key, ar.Data.EncryptString)
	if err != nil {
		return nil, err
	}

	// 解密后: {Iplist, SigB64, UpdateTime}
	var data iplistCache
	if err = json.Unmarshal(plain, &data); err != nil {
		return nil, err
	}
	if data.SigB64 == "" {
		return nil, errors.New("GetIplist 响应缺少 SigB64 签名")
	}
	if data.UpdateTime <= 0 {
		return nil, errors.New("GetIplist 响应缺少 UpdateTime")
	}
	if err = verifyIplistSig(data.Iplist, data.UpdateTime, data.SigB64); err != nil {
		return nil, errors.New("GetIplist ECDSA 验签失败: " + err.Error())
	}
	if len(data.Iplist) == 0 {
		return nil, errors.New("服务端未配置服务器列表")
	}
	return &data, nil
}

// iplistCachePath 本地服务器列表缓存文件路径
// Windows 下为 %LOCALAPPDATA%\.MspTool\ServerList.dat
func iplistCachePath() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.Getenv("APPDATA")
	}
	if base == "" {
		if exe, exeErr := os.Executable(); exeErr == nil {
			base = filepath.Dir(exe)
		}
	}
	return filepath.Join(base, iplistCacheDir, iplistCacheFile)
}

// iplistCacheKey 派生本地缓存密钥：SHA256("MspKeyPro::SrvLst::Cache::v1")，与 Python SDK 一致
func iplistCacheKey() []byte {
	sum := sha256.Sum256([]byte(iplistRc4Key + iplistCacheSalt))
	return sum[:]
}

// rc4Crypt 用指定密钥做 RC4 加解密（加解密同一操作）
func rc4Crypt(key, data []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return out, nil
}

// readIplistCache 读取并解密本地缓存，文件不存在或内容非法时返回错误
// 缓存中必须包含 SigB64 签名，否则认为缓存非法需要重新拉取
func readIplistCache() (*iplistCache, error) {
	raw, err := os.ReadFile(iplistCachePath())
	if err != nil {
		return nil, err
	}
	encrypted := strings.TrimSpace(string(raw))
	if encrypted == "" {
		return nil, errors.New("本地服务器列表为空")
	}
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	plain, err := rc4Crypt(iplistCacheKey(), decoded)
	if err != nil {
		return nil, err
	}
	var c iplistCache
	if err = json.Unmarshal(plain, &c); err != nil {
		return nil, err
	}
	if len(c.Iplist) == 0 {
		return nil, errors.New("本地服务器列表为空")
	}

	// 缓存验签：必须有 SigB64 与 UpdateTime，否则视为旧格式/非法缓存需要重新拉取
	if c.SigB64 == "" {
		return nil, errors.New("本地缓存缺少签名，视为无效")
	}
	if c.UpdateTime <= 0 {
		return nil, errors.New("本地缓存缺少更新时间，视为无效")
	}
	if err = verifyIplistSig(c.Iplist, c.UpdateTime, c.SigB64); err != nil {
		return nil, errors.New("本地缓存 ECDSA 验签失败，可能被篡改: " + err.Error())
	}

	return &c, nil
}

// writeIplistCache 加密并写入本地缓存（紧凑 JSON + RC4 + Base64 + 原子写入）
func writeIplistCache(c *iplistCache) error {
	path := iplistCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	encrypted, err := rc4Crypt(iplistCacheKey(), raw)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, []byte(base64.StdEncoding.EncodeToString(encrypted)), 0o644); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	setHidden(path)
	return nil
}

// refreshIplist 到期后与服务端重新同步（失败保留本地缓存）
func refreshIplist(c *iplistCache) {
	fresh, err := fetchIplist(LockHost)
	if err != nil {
		return
	}
	*c = *fresh
	_ = writeIplistCache(c)
}

// pickIplist 依次检测列表内的服务器，返回第一个可用的
func pickIplist(list []string) (string, bool) {
	for _, ip := range list {
		if pingServer(ip) == nil {
			return ip, true
		}
	}
	return "", false
}

// sameIplist 比较两个服务器列表是否一致（忽略顺序，与 Python SDK 一致）
func sameIplist(a, b []string) bool {
	x := slices.Clone(a)
	y := slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// loadBalancing 负载均衡
// 优先使用本地服务器列表；本地不存在或超过 iplistRefreshInterval 时从服务端同步；
// 到期时间以服务端签名的 UpdateTime 为准（客户端无法篡改）；
// 列表全部不可用则重新拉取，最终回退返回列表第一个地址（与 Python SDK 一致）
func loadBalancing(IP string) (string, error) {
	//判断是否群主服务器
	if IP != LockHost {
		return IP, nil
	}

	// 获取服务器列表：本地缓存优先，拉取失败降级使用本地，完全无数据时用兜底列表
	cache, err := readIplistCache()
	if err != nil {
		// 本地无缓存/缓存非法：拉取成功则保存，失败则使用兜底列表（不写缓存）
		cache = &iplistCache{Iplist: defaultIplist}
		if fresh, ferr := fetchIplist(IP); ferr == nil {
			cache = fresh
			_ = writeIplistCache(cache)
		}
	} else if time.Now().Unix()-cache.UpdateTime >= int64(iplistRefreshInterval/time.Second) {
		// 到达校验周期，先与服务端同步（失败保留本地）
		refreshIplist(cache)
	}

	// 依次尝试本地列表中的服务器
	if ip, ok := pickIplist(cache.Iplist); ok {
		return ip, nil
	}

	// 本地列表全部不可用，尝试重新拉取，与本地不一致才覆盖缓存
	if fresh, ferr := fetchIplist(IP); ferr == nil && !sameIplist(fresh.Iplist, cache.Iplist) {
		cache = fresh
		_ = writeIplistCache(cache)
		if ip, ok := pickIplist(cache.Iplist); ok {
			return ip, nil
		}
	}

	// 最终回退：返回列表第一个地址
	if len(cache.Iplist) > 0 {
		return cache.Iplist[0], nil
	}
	return defaultIplist[0], nil
}
