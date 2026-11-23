//go:build !windows

package main

// 非 Windows 平台没有 GBK 解码的标准库实现，原样返回（UTF-8 环境可能乱码）。
func decodeGBK(b []byte) string { return string(b) }
