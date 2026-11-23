//go:build !windows

package main

import "os"

// 其他平台终端原生支持 ANSI。
func enableVirtualTerminal() {}

func stdoutIsTerminal() bool { return isTerminal(os.Stdout) }
