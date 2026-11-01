package HotKey

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// 修饰键常量，对应 Windows MOD_* 值，可按位或组合（如 ModControl|ModAlt）
const (
	ModNone    = 0x0000 // 无修饰键
	ModAlt     = 0x0001 // Alt
	ModControl = 0x0002 // Ctrl
	ModShift   = 0x0004 // Shift
	ModWin     = 0x0008 // Win
)

const (
	wmHotkey = 0x0312 // WM_HOTKEY
	wmQuit   = 0x0012 // WM_QUIT
)

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procRegisterHotKey     = user32.NewProc("RegisterHotKey")
	procUnregisterHotKey   = user32.NewProc("UnregisterHotKey")
	procGetMessage         = user32.NewProc("GetMessageW")
	procPostThreadMessage  = user32.NewProc("PostThreadMessageW")
	procGetCurrentThreadID = kernel32.NewProc("GetCurrentThreadId")
)

// MSG 对应 Windows MSG 结构体（64 位布局，共 48 字节）
type MSG struct {
	HWND    uintptr
	Message uint32
	_       uint32 // 对齐填充
	WPARAM  uintptr
	LPARAM  uintptr
	Time    uint32
	PT      struct{ X, Y int32 }
}

// Hotkeys 注册热键方法
type Hotkeys struct {
	mu       sync.Mutex
	list     []key
	nextID   int
	started  bool
	threadID uint32
	stopped  chan struct{}
}

type key struct {
	ID        int    // Unique id
	Modifiers int    // Mask of modifiers
	KeyCode   int    // Key code, e.g. 'A'
	Callback  func() //回调方法
}

// AddHotkey 添加热键（必须在 Register 之前调用）
// mod 修饰键使用 ModNone/ModAlt/ModControl/ModShift/ModWin，可按位或组合
func (c *Hotkeys) AddHotkey(keycode, mod int, Callback func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	c.list = append(c.list, key{ID: c.nextID, Modifiers: mod, KeyCode: keycode, Callback: Callback})
}

// Register 执行热键注册，成功后后台阻塞监听热键消息
// 回调函数在监听 goroutine 中串行执行
func (c *Hotkeys) Register() error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("热键已注册，请勿重复调用")
	}
	c.started = true
	c.stopped = make(chan struct{})
	c.mu.Unlock()

	errCh := make(chan error, 1)
	go c.loop(errCh)
	return <-errCh
}

// Unregister 注销所有热键并停止后台监听
func (c *Hotkeys) Unregister() {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return
	}
	tid := c.threadID
	stopped := c.stopped
	c.mu.Unlock()

	// 向消息循环线程投递 WM_QUIT，使其退出
	procPostThreadMessage.Call(uintptr(tid), wmQuit, 0, 0)
	<-stopped
}

// loop 热键消息循环，整个生命周期锁定在同一个 OS 线程上：
// RegisterHotKey(hwnd=0) 会将 WM_HOTKEY 投递到注册线程的消息队列，
// 因此注册与取消息必须在同一线程，否则收不到热键消息
func (c *Hotkeys) loop(errCh chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid, _, _ := procGetCurrentThreadID.Call()

	c.mu.Lock()
	c.threadID = uint32(tid)
	keys := append([]key(nil), c.list...) // 快照，之后不再访问 c.list
	c.mu.Unlock()

	// 注册全部热键，失败时回滚已注册的
	registered := make([]int, 0, len(keys))
	for _, v := range keys {
		r1, _, _ := procRegisterHotKey.Call(0, uintptr(v.ID), uintptr(v.Modifiers), uintptr(v.KeyCode))
		if r1 != 1 {
			for _, id := range registered {
				procUnregisterHotKey.Call(0, uintptr(id))
			}
			c.mu.Lock()
			c.started = false
			c.mu.Unlock()
			errCh <- fmt.Errorf("热键注册失败 (ID:%d KeyCode:%d Mod:%#x)", v.ID, v.KeyCode, v.Modifiers)
			return
		}
		registered = append(registered, v.ID)
	}
	errCh <- nil

	// 阻塞式消息循环：无消息时线程挂起，不消耗 CPU
	var msg MSG
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 { // 收到 WM_QUIT，退出循环
			break
		}
		if ret == ^uintptr(0) { // 调用失败(-1)，忽略本次
			continue
		}
		if msg.Message != wmHotkey {
			continue
		}
		id := int(msg.WPARAM)
		for _, v := range keys {
			if v.ID == id {
				v.Callback()
				break
			}
		}
	}

	// 退出前注销所有热键
	for _, id := range registered {
		procUnregisterHotKey.Call(0, uintptr(id))
	}
	c.mu.Lock()
	c.started = false
	c.mu.Unlock()
	close(c.stopped)
}
