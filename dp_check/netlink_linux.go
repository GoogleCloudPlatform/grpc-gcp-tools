//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"net"

	"google3/third_party/golang/netlink/netlink"
)

type netlinkRoute struct {
	netlink.Route
}

func (n *netlinkRoute) String() string {
	return n.Dst.String()
}

func logLocalRoutes(iface net.Interface, addrFamilyLen int) error {
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
	infoLog.Printf("List all %v routes on network interface |Name: %s, hardware address: %s, flags: %s| returned by |netlink.LinkByName(%s)|", addrFamilyStr, iface.Name, iface.HardwareAddr, iface.Flags, iface.Name)
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}
	rl, err := netlink.RouteList(link, netLinkFamily)
	if err != nil {
		return fmt.Errorf("\"RouteList(link, addrFamily)\" failed: %v", err)
	}
	for _, r := range rl {
		infoLog.Printf("Found %v route: |%s| on network interface |%s|", netLinkFamily, r, iface.Name)
	}
	return nil
}
