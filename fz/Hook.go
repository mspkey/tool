package fz

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"
)

type Hook struct {
	pid         int    //pid
	hookAddress int    //hook的地址
	NewAddress  int    //申请的内存地址
	bak         []byte //保存被破坏的指令
	isHook      bool   //hook是否安装
}

// InlineHook 内存HOOK
//HookAddress hook地址
//length 破坏指令长度
//IsBak是否还原破坏指令  默认为true  防止程序崩溃
func (c *Hook) InlineHook(pid, HookAddress, length int, ShellCode []byte, IsBak bool) error {
	if c.isHook == true {
		return errors.New("hook已安装,请勿重复安装")
	}

	p := &Memory{}
	err := p.OpenProcess(pid)
	if err != nil {
		return err
	}
	defer p.Close()
	c.pid = pid
	err = p.VirtualProtectEx(HookAddress, 20)

	//读取被破坏的指令 以便日后还原
	buff := make([]byte, length)
	c.hookAddress = HookAddress
	err = p.ReadMemory(c.hookAddress, unsafe.Pointer(&buff[0]), length)
	if err != nil {
		return err
	}
	c.bak = buff
	c.NewAddress, err = p.VirtualAllocEx(128)
	if err != nil {
		return err
	}
	var EIP = c.NewAddress

	if cap(ShellCode) != 0 {
		err = p.WriteMemory(EIP, unsafe.Pointer(&ShellCode[0]), len(ShellCode))
		if err != nil {
			return err
		}
		EIP += len(ShellCode)
	}

	if IsBak == true {
		//还原代码
		err = p.WriteMemory(EIP, unsafe.Pointer(&buff[0]), len(buff))
		if err != nil {
			return err
		}
		EIP += len(buff)
	}

	//写入出去的jmp代码
	jmpE9 := JmpE9(c.hookAddress+5, EIP)
	err = p.WriteMemory(EIP, unsafe.Pointer(&jmpE9[0]), 5)
	if err != nil {
		return err
	}
	//写入jmp 进入的代码
	nopCode := []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
	jmpE := JmpE9(c.NewAddress, c.hookAddress)
	err = p.WriteMemory(c.hookAddress, unsafe.Pointer(&nopCode[0]), length)
	err = p.WriteMemory(c.hookAddress, unsafe.Pointer(&jmpE[0]), 5)
	if err != nil {
		return err
	}
	c.isHook = true
	return nil
}

// UnHook 还原hook
func (c *Hook) UnHook() {
	if c.isHook == false {
		return
	}
	p := &Memory{}
	err := p.OpenProcess(c.pid)
	if err != nil {
		return
	}
	defer p.Close()
	if c.bak == nil {
		return
	}
	_ = p.WriteMemory(c.hookAddress, unsafe.Pointer(&c.bak[0]), len(c.bak))
	c.isHook = false

}

// JmpE9 距离 ＝ 目标地址 － (当前地址 ＋ 5)
//NewAddress 目标地址
//OldAddress 当前地址
func JmpE9(NewAddress, thisAddress int) [5]byte {
	s := NewAddress - (thisAddress + 5)
	p := unsafe.Pointer(&s)
	q := (*[4]byte)(p)
	var jmp = [5]byte{0xe9}
	copy(jmp[1:], q[0:])
	return jmp
}

// IntToBytes 整数型转字节集
func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

// Reverse 数组倒序
func Reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
		}
	return s
}
