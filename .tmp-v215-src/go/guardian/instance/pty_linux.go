//go:build linux

package instance

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func openPty() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := grantpt(master); err != nil {
		master.Close()
		return nil, nil, err
	}
	if err := unlockpt(master); err != nil {
		master.Close()
		return nil, nil, err
	}
	name, err := ptsname(master)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func grantpt(f *os.File) error {
	var n int32
	return ioctl(f.Fd(), 0x80045430, uintptr(unsafe.Pointer(&n)))
}

func unlockpt(f *os.File) error {
	var u int32 = 0
	return ioctl(f.Fd(), 0x40045431, uintptr(unsafe.Pointer(&u)))
}

func ptsname(f *os.File) (string, error) {
	var n int32
	if err := ioctl(f.Fd(), 0x80045430, uintptr(unsafe.Pointer(&n))); err != nil {
		return "", err
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}

func ioctl(fd uintptr, cmd uintptr, ptr uintptr) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, ptr)
	if e != 0 {
		return syscall.Errno(e)
	}
	return nil
}
