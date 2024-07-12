package HotKey

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Hotkeys 注册热键方法
type Hotkeys struct {
	list []key
	i    int
}
type key struct {
	Id        int    // Unique id
	Modifiers int    // Mask of modifiers
	KeyCode   int    // Key code, e.g. 'A'
	CallBalk  func() //回调方法
}

// AddHotkey 添加热键 键代码 模式:0 无 1 ctrl 2alt 回调函数
func (c *Hotkeys) AddHotkey(keycode, mod int, Callback func()) {
	c.i++
	var temp = &key{Id: c.i, Modifiers: mod, KeyCode: keycode, CallBalk: Callback}
	c.list = append(c.list, *temp)
}

// Register 执行热键注册
func (c *Hotkeys) Register() error {
	user32 := syscall.NewLazyDLL("user32.dll")
	reghotkey := user32.NewProc("RegisterHotKey")

	//注册热键
	for _, v := range c.list {
		r1, _, err := reghotkey.Call(
			0, uintptr(v.Id), uintptr(v.Modifiers), uintptr(v.KeyCode))
		if r1 == 1 {
			fmt.Println("热键注册成功:", v)
		} else {
			fmt.Println("热键注册失败", "error:", err)
			return errors.New("热键注册失败")
		}
	}
	go c.run()
	return nil
}

func (c *Hotkeys) run() {
	user32 := syscall.NewLazyDLL("user32.dll")
	peekmsg := user32.NewProc("PeekMessageW")
	type MSG struct {
		HWND   uintptr
		UINT   uintptr
		WPARAM int
		LPARAM int64
		DWORD  int32
		POINT  struct{ X, Y int64 }
	}

	for {
		var msg = &MSG{}
		_, _, _ = peekmsg.Call(uintptr(unsafe.Pointer(msg)), 0, 0, 0, 1)
		// Registered id is in the WPARAM field:
		if id := msg.WPARAM; id != 0 {
			if id > 0 {
				for _, v := range c.list {
					if id == v.Id {
						v.CallBalk()
						break
					}
				}
			}
		}
		time.Sleep(time.Millisecond * 5)
	}

}
