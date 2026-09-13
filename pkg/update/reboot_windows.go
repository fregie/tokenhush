//go:build windows

package update

import (
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting  = 0x1
	moveFileDelayUntilReboot = 0x4
)

var moveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

// scheduleRebootReplace asks Windows to move newPath over target at the next
// reboot, the only way to replace a running executable without a second
// process. It is best effort; the journal-based Recover path is the fallback.
func scheduleRebootReplace(newPath, target string) bool {
	from, err := syscall.UTF16PtrFromString(newPath)
	if err != nil {
		return false
	}
	to, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return false
	}
	r1, _, _ := moveFileExW.Call(
		uintptr(unsafe.Pointer(from)),
		uintptr(unsafe.Pointer(to)),
		uintptr(moveFileReplaceExisting|moveFileDelayUntilReboot),
	)
	return r1 != 0
}
