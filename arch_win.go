//go:build windows

package main

const haveChroot = false

var DefaultChroot = ""

func doChroot(path string) error {
	panic("OS does not support chroot")
}
