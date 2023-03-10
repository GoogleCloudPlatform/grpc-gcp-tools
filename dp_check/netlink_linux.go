//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

type netlinkRoute struct {
	netlink.Route
}

func (n *netlinkRoute) String() string {
	return n.Dst.String()
}

func findLocalRoute(iface net.Interface, addrFamilyLen int, routeMatches func(r Route) bool) error {
	var addrFamilyStr string
	var netLinkFamily int
	if addrFamilyLen == net.IPv4len {
		addrFamilyStr = "IPv4"
		netLinkFamily = netlink.FAMILY_V4
	} else if addrFamilyLen == net.IPv6len {
		addrFamilyStr = "IPv6"
		netLinkFamily = netlink.FAMILY_V6
	} else {
		return fmt.Errorf("Invalid address family length %v is not IPv4 or IPv6", addrFamilyLen)
	}
	infoLog.Printf("Check all %v routes on network interface |Name: %s, hardware address: %s, flags: %s| returned by |netlink.LinkByName(%s)|", addrFamilyStr, iface.Name, iface.HardwareAddr, iface.Flags, iface.Name)
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}
	rl, err := netlink.RouteList(link, netLinkFamily)
	if err != nil {
		return fmt.Errorf("\"RouteList(link, addrFamily)\" failed: %v", err)
	}
	foundMatch := false
	for _, r := range rl {
		infoLog.Printf("Found %v route: |%s| on network interface |%s|", netLinkFamily, r, iface.Name)
		if routeMatches(&netlinkRoute{r}) {
			foundMatch = true
		}
	}
	if !foundMatch {
		return fmt.Errorf("failed to find matching route")
	}
	return nil
}
