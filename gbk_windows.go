//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// decodeGBK 使用 Windows 代码页 936 解码纯真数据库的 GBK 字符串。
func decodeGBK(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	k := syscall.NewLazyDLL("kernel32.dll")
	p := k.NewProc("MultiByteToWideChar")
	const cpGBK = 936
	const mbPrecomposed = 1
	n, _, _ := p.Call(cpGBK, mbPrecomposed, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0, 0)
	if n <= 0 {
		return string(b)
	}
	out := make([]uint16, n)
	p.Call(cpGBK, mbPrecomposed, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&out[0])), n)
	return syscall.UTF16ToString(out)
}
