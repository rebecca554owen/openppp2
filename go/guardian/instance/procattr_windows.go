//go:build windows

package instance

import "syscall"

func procAttrForPTY(_ uintptr) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
