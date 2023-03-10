//go:build windows
// +build windows

package main

import (
	"net"
)

func findLocalRoute(iface net.Interface, addrFamilyLen int, routeMatches func(r Route) bool) error {
	infoLog.Printf("Skipping local route checks for Windows")
	return nil
}
