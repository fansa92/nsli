//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVirtualTerminal 在 Windows 10+ 控制台启用 ANSI 转义序列支持。
func enableVirtualTerminal() {
	k := syscall.NewLazyDLL("kernel32.dll")
	getStd := k.NewProc("GetStdHandle")
	getMode := k.NewProc("GetConsoleMode")
	setMode := k.NewProc("SetConsoleMode")
	const stdOutputHandle = ^uintptr(10)
	h, _, _ := getStd.Call(stdOutputHandle)
	if h == 0 || h == ^uintptr(0) {
		return
	}
	var mode uint32
	if r, _, _ := getMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	const enableVT = 0x0004
	_, _, _ = setMode.Call(h, uintptr(mode|enableVT))
}

func stdoutIsTerminal() bool { return isTerminal(os.Stdout) }
