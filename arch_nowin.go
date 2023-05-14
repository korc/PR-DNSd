//go:build !windows

package main

import "syscall"

const haveChroot = true

var DefaultChroot = "/var/tmp"

func doChroot(path string) error {
	return syscall.Chroot(path)
}
