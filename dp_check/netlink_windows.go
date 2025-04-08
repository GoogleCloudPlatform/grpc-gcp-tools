//go:build windows
// +build windows

package main

import (
	"net"
)

func logLocalRoutes(iface net.Interface, addrFamilyLen int) error {
	infoLog.Printf("Skipping local route logging for Windows")
	return nil
}
