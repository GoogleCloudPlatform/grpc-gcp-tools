/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// dp_check is a command line tool for checking the proper configuration and setup of both a
// VM (the one that it's being ran on) and a service with respect to DirectPath.
// This program is meant to be ran only on DirectPath-enabled VM's, and it's intended to be
// compiled in a VM.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	// TODO(apolcyn): depend on a canonical version of grpclb protos
	"google.golang.org/grpc"
	lbgrpc "google.golang.org/grpc/balancer/grpclb/grpc_lb_v1"
	lbpb "google.golang.org/grpc/balancer/grpclb/grpc_lb_v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/alts"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	_ "github.com/GoogleCloudPlatform/grpc-gcp-tools/proto/grpc_lookup_v1"
	v3clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	v3corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	v3listenerpb "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	v3clusterextpb "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/aggregate/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/fault/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	v3httppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/load_balancing_policies/client_side_weighted_round_robin/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/load_balancing_policies/pick_first/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/load_balancing_policies/ring_hash/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/load_balancing_policies/round_robin/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/load_balancing_policies/wrr_locality/v3"
	v3adsgrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	v3discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

var (
	service = flag.String("service", "", `Required. The public DirectPath-enabled DNS of the service to check.

Note: this can also be a literal IP:port address. In this case, use the --skip flag to skip load balancer interactions, and
set --ipv4_only or --ipv6_only depending on whether the literal is IPv4 or IPv6, respectively. For example, if the
literal is an IPv6 address, use flags:
    --skip="Service SRV DNS queries,TCP/IPv6 connectivity to load balancers,Discovery of IPv6 backends via load balancers"
    --ipv6_only`)
	ipv4Only = flag.Bool("ipv4_only", false, `Optional. Skip all IPv6-specific checks. Mainly useful if one knows
that IPv6 checks would otherwise fail in benign ways.`)
	ipv6Only = flag.Bool("ipv6_only", false, `Optional. Skip all IPv4-specific checks. Mainly useful if one knows
that IPv4 checks would otherwise fail in benign ways.`)
	ipv4AndV6 = flag.Bool("ipv4_and_v6", false, `Optional. Run every IPv4 and IPv6 check and effectively disable
automatic skipping of checks. Note that this may cause dp_check to fail in an overly conversative way, when DirectPath
RPCs could still pass. Also note that if --service is IPv6-only, then this flag will cause dp_check to always fail.`)
	skip = flag.String("skip", "", `Optional. A comma-separated list of checks to skip. The default behavior
(when set to the empty string) is to not skip any checks.

Example to run only the IPv6 address and route checks: --skip="IPv6 Addresses,IPv6 routes".

Note that this is an unstable API because check names are prone to change, prefer --ipv4_only or --ipv6_only if skips are needed.
`)
	balancerTargetOverride = flag.String("balancer_target_override", "", `Optional. The target hostname (must be a DNS name for secure naming purposes), including
port number, of the load balancer. This is mainly useful if one would like to check the proper setup of a VM and service with respect
to e.g. DirectPath networking and load balancing, in such a way that ignores DNS SRV resolution. In most use cases, it would be desirable to set this
in conjunction with --skip="Service SRV DNS queries".`)
	checkGrpclb                 = flag.Bool("check_grpclb", false, `Optional. Perform checks related to getting backend addresses from grpclb.`)
	checkXds                    = flag.Bool("check_xds", true, `Optional. Add extra checks to get backend addresses from Traffic Director.`)
	userAgent                   = flag.String("user_agent", "", "Optional. The user agent header to use on RPCs to the load balancer")
	trafficDirectorHostname     = flag.String("td_hostname", "directpath-pa.googleapis.com", `Optional. Override the Traffic Director hostname. Do not include a port number.`)
	xdsExpectFallbackConfigured = flag.Bool("xds_expect_fallback_configured", false, "Optional. Whether or not we expect CFE fallback to be configured for this service in Traffic Director.")
	infoLog                     = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	failureCount                int
	runningOS                   = runtime.GOOS
)

type (
	adsStream     v3adsgrpc.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	platformError string
)

// Allow passing an raw literal ip:port address in the --service flag.
// This behavior can be used in conjunction with the --skip flag to test p2p connectivity.
func maybeInitBackendAddrsFromFlags(addrLen int) []string {
	ip, port, err := net.SplitHostPort(*service)
	if err != nil {
		return []string{}
	}
	s := net.ParseIP(ip)
	if s == nil {
		return []string{}
	}
	if s.To4() != nil {
		// IPv4
		if addrLen == net.IPv4len {
			return []string{net.JoinHostPort(ip, port)}
		}
		return []string{}
	}
	// IPv6
	if addrLen == net.IPv6len {
		return []string{net.JoinHostPort(ip, port)}
	}
	return []string{}
}

// Route an interface that is platform agnostic which provides a string representation
// of the dst route.
type Route interface {
	String() string
}

func (k platformError) Error() string {
	return fmt.Sprintf("%s is not supported", string(k))
}

const (
	jsonIndent               = "  "
	loadBalancerIPv6OnlyDNS  = "grpclb.directpath.google.internal."
	loadBalancerDualstackDNS = "grpclb-dualstack.directpath.google.internal."
	defaultLoadBalancerPort  = 9355
	linuxProductNameFile     = "/sys/class/dmi/id/product_name"
	windowsManufacturerRegex = ":(.*)"
	windowsCheckCommand      = "powershell.exe"
	windowsCheckCommandArgs  = "Get-WmiObject -Class Win32_BIOS"
	powershellOutputFilter   = "Manufacturer"

	trafficDirectorPort             = "443"
	userAgentName                   = "dp-check"
	userAgentVersion                = "1.11"
	clientFeatureNoOverprovisioning = "envoy.lb.does_not_support_overprovisioning"
	ipv6CapableMetadataName         = "TRAFFICDIRECTOR_DIRECTPATH_C2P_IPV6_CAPABLE"
	zoneURL                         = "http://metadata.google.internal/computeMetadata/v1/instance/zone"
	// V3ListenerURL is typeURL of v3 xDS Listener
	V3ListenerURL = "type.googleapis.com/envoy.config.listener.v3.Listener"
	// V3RouteConfigURL is typeURL of v3 xDS RouteConfiguration
	V3RouteConfigURL = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"
	// V3ClusterURL is typeURL of v3 xDS Cluster
	V3ClusterURL = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	// V3EndpointsURL is typeURL of v3 xDS ClusterLoadAssignment
	V3EndpointsURL = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"
)

type skipCheckError struct {
	err error
}

func (s *skipCheckError) Error() string {
	return s.err.Error()
}

func cmd(command string) (string, error) {
	c := strings.Split(command, " ")
	out, err := exec.Command(c[0], c[1:]...).Output()
	return string(out), err
}

func fetchIPFromMetadataServer(addrFamilyStr string) (*net.IP, error) {
	const metadataServerPrimaryNICPath = "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0"
	var metadataServerURL string
	if addrFamilyStr == "IPv4" {
		metadataServerURL = metadataServerPrimaryNICPath + "/ip"
	} else if addrFamilyStr == "IPv6" {
		metadataServerURL = metadataServerPrimaryNICPath + "/ipv6s"
	} else {
		return nil, fmt.Errorf("Invalid address family %v is not IPv4 or IPv6", addrFamilyStr)
	}
	client := &http.Client{}
	infoLog.Printf("Check if this VM has a %v address allocated to its primary network interface by sending http GET request to: %v", addrFamilyStr, metadataServerURL)
	req, err := http.NewRequest("GET", metadataServerURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 200 {
		address := net.ParseIP(strings.TrimSuffix(string(body), "\n"))
		infoLog.Printf("Received %v address %s from metadata server", addrFamilyStr, address)
		return &address, nil
	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("This VM doesn't have a %v address allocated to its primary network interface", addrFamilyStr)
	}
	return nil, fmt.Errorf("Received status code %d in response to metadata server GET request to URL: %s. This is unexpected (we only expect status codes 200 or 404), and so this may indicate a bug", resp.StatusCode, metadataServerURL)
}

func skipLoopback(iface net.Interface) error {
	if iface.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("interface has loopback flag")
	}
	if iface.Flags&net.FlagUp != net.FlagUp {
		return fmt.Errorf("interface is not marked up")
	}
	return nil
}

func skipNonLoopback(iface net.Interface) error {
	if iface.Flags&net.FlagLoopback == 0 {
		return fmt.Errorf("interface does not have loopback flag")
	}
	if iface.Flags&net.FlagUp != net.FlagUp {
		return fmt.Errorf("interface is not marked up")
	}
	return nil
}

func findLocalAddress(ipMatches func(net.IP) bool, ifaceFilter func(iface net.Interface) error) (*net.Interface, error) {
	infoLog.Println("Check local addresses by iterating over all ip addresses from interfaces returned by: |net.Interfaces()|")
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var match net.Interface
	foundMatch := false
	for _, iface := range ifaces {
		if err := ifaceFilter(iface); err != nil {
			infoLog.Printf("Not checking interface: |Name: %s, hardware address: %s, flags: %s| because: %v", iface.Name, iface.HardwareAddr, iface.Flags, err)
			continue
		}
		infoLog.Printf("Checking up network interface: |Name: %s, hardware address: %s, flags: %s|", iface.Name, iface.HardwareAddr, iface.Flags)
		ifaddrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, ifaddr := range ifaddrs {
			ip := ifaddr.(*net.IPNet).IP
			infoLog.Printf("Found ip address |%s| when checking network interface |%s|", ip.String(), iface.Name)
			if ipMatches(ip) {
				match = iface
				foundMatch = true
			}
		}
	}
	if !foundMatch {
		return nil, fmt.Errorf("failed to find matching address")
	}
	infoLog.Printf("Found the valid directpath network interface %s with hardware address |%s| and flags %s", match.Name, match.HardwareAddr, match.Flags)
	return &match, nil
}

func checkLocalIPv6Addresses(ipv6FromMetadataServer *net.IP) (*net.Interface, error) {
	if ipv6FromMetadataServer == nil {
		return nil, fmt.Errorf("skipping search for DirectPath-capable IPv6 address because the VM failed to get a valid IPv6 address from metadata server")
	}
	var err error
	var iface *net.Interface
	if iface, err = findLocalAddress(func(ip net.IP) bool { return ip.To4() == nil && ip.Equal(*ipv6FromMetadataServer) }, skipLoopback); err != nil {
		return nil, fmt.Errorf("failed to find local DirectPath-capable IPv6 address: %v. This VM was expected to have a network interface with IPv6 address: %s assigned to it, but no such interface was found, it's likely that IPv6 DHCP setup either failed or hasn't been attempted", err, ipv6FromMetadataServer)
	}
	return iface, nil
}

func checkLocalIPv6LoopbackAddress(ipv6FromMetadataServer *net.IP) error {
	if ipv6FromMetadataServer == nil {
		return fmt.Errorf("skipping search for IPv6 loopback address because the VM failed to get a valid IPv6 address from metadata server")
	}
	var err error
	ipv6Loopback := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1}
	if _, err = findLocalAddress(func(ip net.IP) bool { return ip.To4() == nil && ip.Equal(ipv6Loopback) }, skipNonLoopback); err != nil {
		return fmt.Errorf(`failed to find local IPv6 loopback address "::1" because: %v. Although this isn't inherently needed for Directpath connectivity, some gRPC client releases use a presence of the IPv6 loopback address as a heuristic to determine if the local runtime environment supports IPv6. So a lack of this address might prevent the client from being able to use IPv6`, err)
	}
	return nil
}

func checkLocalIPv4Addresses(ipv4FromMetadataServer *net.IP) (*net.Interface, error) {
	if ipv4FromMetadataServer == nil {
		return nil, fmt.Errorf("skipping search for DirectPath-capable IPv4 address because the VM failed to get a valid IPv4 address from metadata server")
	}
	var err error
	var iface *net.Interface
	if iface, err = findLocalAddress(func(ip net.IP) bool { return ip.To4() != nil && ip.Equal(*ipv4FromMetadataServer) }, skipLoopback); err != nil {
		return nil, fmt.Errorf("failed to find local DirectPath-capable IPv4 address: %v. This VM was expected to have a network interface with IPv4 address: %s assigned to it, but no such interface was found", err, ipv4FromMetadataServer)
	}
	return iface, nil
}

func checkLocalIPv6Routes(directPathIPv6NetworkInterface *net.Interface) error {
	if directPathIPv6NetworkInterface == nil {
		return fmt.Errorf("skipping IPv6 routes check because there is no valid directpath IPv6 network interface on this machine")
	}
	const route = "2001:4860:8040::/42"
	infoLog.Printf("Search for an IPv6 route on network interface: %v matching: %v", directPathIPv6NetworkInterface.Name, route)
	if err := findLocalRoute(*directPathIPv6NetworkInterface, net.IPv6len, func(r Route) bool {
		return strings.Contains(r.String(), route)
	}); err != nil {
		return fmt.Errorf("Missing route prefix to backends: 2001:4860:8040::/42. IPv6 route setup likely either failed or hasn't been attempted. err: %v", err)
	}
	return nil
}

func checkLocalIPv4Routes(directPathIPv4NetworkInterface *net.Interface, ipv4FromMetadataServer *net.IP, ipv4BalancerIPs []net.IP, balancerPort string) error {
	if directPathIPv4NetworkInterface == nil {
		return fmt.Errorf("skipping IPv4 routes check because there is not valid DirectPath IPv4 network interface on this machine")
	}
	if len(ipv4BalancerIPs) == 0 {
		return fmt.Errorf("skipping IPv4 routes check because we didn't find any IPv4 load balancer addresses")
	}
	// First just log the routes on the candidate interface
	if err := findLocalRoute(*directPathIPv4NetworkInterface, net.IPv4len, func(r Route) bool { return true }); err != nil {
		return err
	}
	sourceStr := net.JoinHostPort(ipv4FromMetadataServer.String(), "0")
	destStr := net.JoinHostPort(ipv4BalancerIPs[0].String(), balancerPort)
	infoLog.Printf("Check kernel routability of DirectPath/IPv4 by opening a UDP socket, binding it to %v and calling connect for %v", sourceStr, destStr)
	// Also see https://github.com/golang/go/issues/10552#issuecomment-115540597 for this strategy.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("error creating IPv4/UDP socket: %v", err)
	}
	source := &syscall.SockaddrInet4{Port: 0}
	for i := 0; i < 4; i++ {
		source.Addr[i] = (*ipv4FromMetadataServer)[i]
	}
	if err := syscall.Bind(fd, source); err != nil {
		return fmt.Errorf("error binding UDP/IPV4 socket to %v: %v", sourceStr, err)
	}
	port, _ := strconv.Atoi(balancerPort)
	dest := &syscall.SockaddrInet4{Port: port}
	for i := 0; i < 4; i++ {
		dest.Addr[i] = ipv4BalancerIPs[0][i]
	}
	if err := syscall.Connect(fd, dest); err != nil {
		return fmt.Errorf("failed to connect UDP socket (source: %v) to dest: %v, err: %v. This indicates the DirectPath/IPv4 backends aren't routable from this VM", sourceStr, destStr, err)
	}
	return nil
}

func getBackendAddrsFromGrpclb(lbAddr string, balancerHostname string, srvQueriesSucceeded bool) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	altsCreds := alts.NewClientCreds(alts.DefaultClientOptions())
	altsCreds.OverrideServerName(balancerHostname)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(altsCreds),
		grpc.WithBlock(),
	}
	userAgentLogString := fmt.Sprintf(". Note that we are not overriding the user agent, so the grpc-go library will use the default user agent based on the grpc-go library version: |%v|...", grpc.Version)
	if len(*userAgent) > 0 {
		opts = append(opts, grpc.WithUserAgent(*userAgent))
		userAgentLogString = fmt.Sprintf(" and grpc.WithUserAgent(\"%v\")...", *userAgent)
	}
	infoLog.Printf("Attempt to dial: %v using ALTS and grpc.WithBlock()%v", lbAddr, userAgentLogString)
	conn, err := grpc.DialContext(
		ctx,
		lbAddr,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc connection to balancer: %v", err)
	}
	infoLog.Printf("Successfully dialed balancer. Now send initial grpc request...")
	lbClient := lbgrpc.NewLoadBalancerClient(conn)
	stream, err := lbClient.BalanceLoad(ctx)
	initReq := &lbpb.LoadBalanceRequest{
		LoadBalanceRequestType: &lbpb.LoadBalanceRequest_InitialRequest{
			InitialRequest: &lbpb.InitialLoadBalanceRequest{
				Name: *service,
			},
		},
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open stream to the balancer: %v", err)
	}
	if err := stream.Send(initReq); err != nil {
		return nil, fmt.Errorf("failed to send initial grpc request to balancer: %v", err)
	}
	infoLog.Printf("Successfully sent initial grpc request to balancer: |%v|. Now wait for initial response...", initReq)
	reply, err := stream.Recv()
	if status.Code(err) == codes.InvalidArgument {
		return nil, fmt.Errorf("the BalanceLoad RPC failed with status code %v, error: %v, which indicates that %s is not a DirectPath-enabled service", status.Code(err), err, *service)
	}
	// TODO(apolcyn): remove this check for permission denied once denied requests always result in FallbackResponse messages
	if status.Code(err) == codes.PermissionDenied {
		if srvQueriesSucceeded {
			return nil, fmt.Errorf(`the BalanceLoad stream failed with status code: %v, error: %v. Because the earlier SRV record query for _grpclb._tcp.%s succeeded, this most likely indicates that %s is a DirectPath-enabled service, but that the service is preventing DirectPath access from gRPC clients which send the user agent header that we sent in the BalanceLoad RPC; see logs above for a hint about what the user-agent header is that we just sent. Consider running this tool again but with the --user_agent flag set to a new value, to try a different user agent header`, status.Code(err), err, *service, *service)
		}
		return nil, fmt.Errorf(`the BalanceLoad stream failed with status code: %v, error: %v. Because the earlier SRV record query for _grpclb._tcp.%s failed, this most likely indicates that %s is a DirectPath-enabled service, but that some attribute(s) of this specific VM (for example the VPC network project number of this VM's primary network interface, the VM project number, or the current region or zone we're running in), are causing this VM to be prevented DirectPath access to %s`, status.Code(err), err, *service, *service, *service)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to recv initial grpc response from balancer: %v", err)
	}
	initResp := reply.GetInitialResponse()
	if initResp == nil {
		return nil, fmt.Errorf("gRPC reply from balancer did not include initial response", err)
	}
	infoLog.Printf("Successfully received initial grpc response from balancer: |%v|. Now wait for a serverlist...", initResp)
	// Just wait for the first non-empty server list
	for {
		reply, err = stream.Recv()
		if err != nil {
			return nil, fmt.Errorf("grpc balancer stream Recv error:%v", err)
		}
		if reply.GetFallbackResponse() != nil {
			if srvQueriesSucceeded {
				return nil, fmt.Errorf(`received a FallbackResponse on the BalanceLoad stream. Because the earlier SRV record query for _grpclb._tcp.%s succeeded, this most likely indicates that %s is a DirectPath-enabled service, but that the service is preventing DirectPath access from gRPC clients which send the user agent header that we sent in the BalanceLoad RPC; see logs above for a hint about what the user-agent header is that we just sent. Consider running this tool again but with the --user_agent flag set to a new value, to try a different user agent header`, *service, *service)
			}
			return nil, fmt.Errorf(`received a FallbackResponse on the BalanceLoad stream. Because the earlier SRV record query for _grpclb._tcp.%s failed, this most likely indicates that %s is a DirectPath-enabled service, but that some attribute(s) of this specific VM (for example the VPC network project number of this VM's primary network interface, the VM project number, or the current region or zone we're running in), are causing this VM to be prevented DirectPath access to %s`, *service, *service, *service)
		}
		if serverList := reply.GetServerList(); serverList != nil {
			var out []string
			for _, s := range serverList.Servers {
				if s.Drop {
					continue
				}
				ip := net.IP(s.IpAddress)
				var addrStr string
				if ip.To4() != nil {
					addrStr = fmt.Sprintf("%s:%v", ip.String(), s.Port)
				} else if ip.To16() != nil {
					addrStr = fmt.Sprintf("[%s]:%v", ip.String(), s.Port)
				} else {
					return nil, fmt.Errorf("resolved backend ip:|%v|, which was not recgnoized as a valid IPv4 or IPv6 address", s.IpAddress)
				}
				out = append(out, addrStr)
			}
			if len(out) > 0 {
				return out, nil
			}
		}
	}
}

func resolveBackends(balancerAddress string, balancerHostname string, srvQueriesSucceeded bool) ([]string, error) {
	var addressFamily string
	var matchAddrFamily func(net.IP) bool
	balancerHost, _, err := net.SplitHostPort(balancerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to split balancer address: %v into host and port components", balancerAddress)
	}
	balancerIP := net.ParseIP(balancerHost)
	if balancerIP == nil {
		return nil, fmt.Errorf("failed to parse IP component of balancer address: %v", balancerAddress)
	}
	if balancerIP.To4() != nil {
		addressFamily = "IPv4"
		matchAddrFamily = func(ip net.IP) bool { return ip.To4() != nil }
	} else if balancerIP.To16() != nil {
		addressFamily = "IPv6"
		matchAddrFamily = func(ip net.IP) bool { return ip.To16() != nil }
	} else {
		return nil, fmt.Errorf("balancer IP: %v not recognized as IPv4 or IPv6", balancerIP)
	}
	var backends []string
	infoLog.Printf("Find %v backend addresses for %v by making a \"BalanceLoad\" RPC to the load balancers...", addressFamily, *service)
	if backends, err = getBackendAddrsFromGrpclb(balancerAddress, balancerHostname, srvQueriesSucceeded); err != nil {
		return nil, fmt.Errorf(`Failed to get any %v backend VIPs from the load balancer because: %v.
Consider running this binary under environment variables:
* GRPC_GO_LOG_VERBOSITY_LEVEL=99
* GRPC_GO_LOG_SEVERITY_LEVEL=INFO
in order to get more debug logs from the grpc library (which was just used when reaching out to the load balancer)`, addressFamily, err)
	}
	if !srvQueriesSucceeded {
		infoLog.Printf(`Because we received an assignment from the load balancer, it's unexpected that earlier SRV queries failed. However, one possible reason is that the service is in the process of denying some attributes of this specific VM (for example the VPC network project number of this VM's primary network interface, the VM project number, or the current region or zone we're running in), and that the load balancer will start to respond to our BalanceLoad RPCs for %s with FallbackResponse messages soon.`, *service)
	}
	for _, addr := range backends {
		infoLog.Printf("Found %v backend address:|%v|", addressFamily, addr)
		ipStr, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to split %v into ip and port components: %v", addr, err)
		}
		if ip := net.ParseIP(ipStr); ip == nil || !matchAddrFamily(ip) {
			return nil, fmt.Errorf("ip %v from address %v was not recognized as a valid %v address", ipStr, addr, addressFamily)
		}
	}
	return backends, nil
}

func manufacturerReader() (io.Reader, error) {
	switch runningOS {
	case "linux":
		return os.Open(linuxProductNameFile)
	case "windows":
		cmd := exec.Command(windowsCheckCommand, windowsCheckCommandArgs)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			if strings.HasPrefix(line, powershellOutputFilter) {
				re := regexp.MustCompile(windowsManufacturerRegex)
				name := re.FindString(line)
				name = strings.TrimLeft(name, ":")
				return strings.NewReader(name), nil
			}
		}
		return nil, errors.New("cannot determine the machine's manufacturer")
	default:
		return nil, platformError(runningOS)
	}
}

func readManufacturer() ([]byte, error) {
	reader, err := manufacturerReader()
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, errors.New("got nil reader")
	}
	manufacturer, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed reading %v: %v", linuxProductNameFile, err)
	}
	return manufacturer, nil
}

// isRunningOnGCP checks whether the local system, without doing a network request is
// running on GCP.
func isRunningOnGCP() (bool, error) {
	manufacturer, err := readManufacturer()
	if os.IsNotExist(err) {
		return false, err
	}
	if err != nil {
		return false, fmt.Errorf("failure to read manufacturer information: %v", err)
	}
	name := string(manufacturer)
	switch runtime.GOOS {
	case "linux":
		name = strings.TrimSpace(name)
		return name == "Google" || name == "Google Compute Engine", nil
	case "windows":
		name = strings.Replace(name, " ", "", -1)
		name = strings.Replace(name, "\n", "", -1)
		name = strings.Replace(name, "\r", "", -1)
		return name == "Google", nil
	default:
		return false, platformError(runtime.GOOS)
	}
	return false, nil
}

func checkSecureConnectivityToBackend(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	altsCreds := alts.NewClientCreds(alts.DefaultClientOptions())
	altsCreds.OverrideServerName(*service)
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(altsCreds))
	const errMsg = "Secure connectivity to backend addr - %v failed: %v."
	if err != nil {
		return fmt.Errorf(errMsg, address, err)
	}
	lastState := conn.GetState()
	for lastState != connectivity.Ready {
		select {
		case <-ctx.Done():
			return fmt.Errorf(errMsg, address, ctx.Err())
		default:
		}
		conn.WaitForStateChange(ctx, lastState)
		lastState = conn.GetState()
	}
	return nil
}

func runCheck(name string, check func() error) {
	if len(*skip) > 0 {
		for _, c := range strings.Split(*skip, ",") {
			if c == name {
				fmt.Printf("\x1b[1m%v: \x1b[34m[SKIPPED. Manually skipped due to inclusion in --skip=\"%v\"\x1b[0m\n", name, *skip)
				return
			}
		}
	}
	if err := check(); err != nil {
		if _, ok := err.(*skipCheckError); ok {
			fmt.Printf("\x1b[1m%v: \x1b[34m[SKIPPED: %v\x1b[0m\n", name, err)
			return
		}
		fmt.Printf("\x1b[1m%v: \x1b[31mFAILED. Error: %v\x1b[0m\n", name, err)
		failureCount++
		return
	}
	fmt.Printf("\x1b[1m%v: \x1b[32mPASSED\x1b[0m\n", name)
}

func openAdsStream(ctx context.Context) (adsStream, error) {
	// use TLS credential
	var roots *x509.CertPool
	tlsCreds := credentials.NewTLS(&tls.Config{RootCAs: roots})
	tlsCreds.OverrideServerName(*trafficDirectorHostname)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithPerRPCCredentials(oauth.NewComputeEngine()),
		grpc.WithBlock(),
	}
	lbAddr := net.JoinHostPort(*trafficDirectorHostname, trafficDirectorPort)
	infoLog.Printf("Attempt to dial |%v| using TLS and we're authenticating as the VM's default service account by fetching a token from the metadata server", lbAddr)
	conn, err := grpc.DialContext(ctx, lbAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc connection to Traffic Director: %v", err)
	}
	lbClient := v3adsgrpc.NewAggregatedDiscoveryServiceClient(conn)
	stream, err := lbClient.StreamAggregatedResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open the stream to Traffic Director: %v", err)
	}
	return stream, nil
}

func sendXdsRequest(stream adsStream, node *v3corepb.Node, typeURL, resourceName string, versionInfoMap, nonceMap map[string]string) (*v3discoverypb.DiscoveryResponse, error) {
	typeNameMap := map[string]string{
		V3ListenerURL:    "LDS",
		V3RouteConfigURL: "RDS",
		V3ClusterURL:     "CDS",
		V3EndpointsURL:   "EDS",
	}
	requestName := typeNameMap[typeURL]
	infoLog.Printf("Now send %v request...", requestName)
	xdsReq := &v3discoverypb.DiscoveryRequest{
		VersionInfo:   versionInfoMap[typeURL],
		Node:          node,
		ResourceNames: []string{resourceName},
		TypeUrl:       typeURL,
		ResponseNonce: nonceMap[typeURL],
	}
	if err := stream.Send(xdsReq); err != nil {
		return nil, fmt.Errorf("failed to send %v request: %v", requestName, err)
	}
	infoLog.Printf("Successfully sent %v request: |%+v|. Now wait for the reply...", requestName, xdsReq)
	xdsReply, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive %v response: %v", requestName, err)
	}
	mm := protojson.MarshalOptions{
		Multiline: true,
		Indent:    jsonIndent,
	}
	encodeXdsReply, err := mm.Marshal(xdsReply)
	if err != nil {
		return nil, fmt.Errorf("failed to pretty-print %v response: %v", requestName, err)
	}
	infoLog.Printf("Successfully received %v reply: |%+v|.", requestName, string(encodeXdsReply))
	versionInfoMap[typeURL] = xdsReply.GetVersionInfo()
	nonceMap[typeURL] = xdsReply.GetNonce()
	if err = ackXdsResponse(stream, node, typeURL, resourceName, versionInfoMap, nonceMap); err != nil {
		return nil, fmt.Errorf("failed to acked %v response: %v", requestName, err)
	}
	infoLog.Printf("Successfully acked %v reply.", requestName)
	return xdsReply, nil
}

func ackXdsResponse(stream adsStream, node *v3corepb.Node, typeURL, resourceName string, versionInfoMap, nonceMap map[string]string) error {
	ackReq := &v3discoverypb.DiscoveryRequest{
		VersionInfo:   versionInfoMap[typeURL],
		Node:          node,
		ResourceNames: []string{resourceName},
		TypeUrl:       typeURL,
		ResponseNonce: nonceMap[typeURL],
	}
	if err := stream.Send(ackReq); err != nil {
		return fmt.Errorf("failed to ack xDS response: %v", err)
	}
	return nil
}

// Extract cluster_name from LDS response
func processLdsResponse(ldsReply *v3discoverypb.DiscoveryResponse) (string, error) {
	if len(ldsReply.GetResources()) == 0 {
		return "", fmt.Errorf("no listener resource received in LDS response")
	}
	if len(ldsReply.GetResources()) != 1 {
		return "", fmt.Errorf("expect to receive only 1 listener resource in LDS response, but received %v. This is not necessarily a violation of the XDS protocol, but it is not supported by (this version) of the dp_check tool", len(ldsReply.GetResources()))
	}
	resource := ldsReply.GetResources()[0]
	lis := &v3listenerpb.Listener{}
	if err := proto.Unmarshal(resource.GetValue(), lis); err != nil {
		return "", fmt.Errorf("failed to unmarshal listener resource from LDS response: %v", err)
	}
	if lis.GetName() != *service {
		return "", fmt.Errorf("listener resource name |%v| does not match |%v|", lis.GetName(), *service)
	}
	apiLis := &v3httppb.HttpConnectionManager{}
	if err := proto.Unmarshal(lis.GetApiListener().GetApiListener().GetValue(), apiLis); err != nil {
		return "", fmt.Errorf("failed to unmarshal api_listener resource from LDS response: %v", err)
	}
	switch apiLis.RouteSpecifier.(type) {
	// TODO(mohanli): Add RDS support when processing LDS response
	case *v3httppb.HttpConnectionManager_Rds:
		return "", fmt.Errorf("route resource type in LDS response is RDS, which is currently not supported in dp_check")
	case *v3httppb.HttpConnectionManager_RouteConfig:
		infoLog.Printf("route resource type in LDS response is route_config")
		for _, vh := range apiLis.GetRouteConfig().GetVirtualHosts() {
			infoLog.Printf("virtual host: |%+v|", vh)
			// The domains field of the VirtualHost must match the backend service
			if len(vh.GetDomains()) == 0 {
				infoLog.Printf("no domain received in this virtual_host, skip this virtual_host")
				continue
			}
			if vh.GetDomains()[0] != "*" && vh.GetDomains()[0] != *service {
				infoLog.Printf("received a virtual_host whose domain is |%v|, which does not match |%v|, skip this virtual_host", vh.GetDomains()[0], *service)
				continue
			}
			// In the initial gRPC xDS design, only interested the default route (the last one)
			if len(vh.GetRoutes()) == 0 {
				infoLog.Printf("no routes received in virtual_host, skip")
				continue
			}
			route := vh.GetRoutes()[len(vh.GetRoutes())-1]
			// The match field in the route must contains a prefix field,
			// and the prefix field must be an empty string
			match := route.GetMatch()
			if match == nil {
				infoLog.Printf("match field must exist, but it is nil, skip this virtual_host")
				continue
			}
			if match.GetPrefix() != "" {
				infoLog.Printf("match field in default route must have an empty prefix, but it is |%v|, skip this virtual_host", match.GetPrefix())
				continue
			}
			// Get cluster name
			return route.GetRoute().GetCluster(), nil
		}
	case nil:
		return "", fmt.Errorf("no route resource in LDS response")
	default:
		return "", fmt.Errorf("unknown route resource type in LDS response: %v", apiLis.RouteSpecifier)
	}
	return "", fmt.Errorf("no matching cluster name found in LDS response")
}

// Extract cluster from CDS response
func getCluster(cdsReply *v3discoverypb.DiscoveryResponse, expectedClusterName string) (*v3clusterpb.Cluster, error) {
	if len(cdsReply.GetResources()) == 0 {
		return nil, fmt.Errorf("no cluster resource received in CDS response")
	}
	if len(cdsReply.GetResources()) != 1 {
		return nil, fmt.Errorf("expect to receive only 1 cluster resource in CDS response, but received %v", len(cdsReply.GetResources()))
	}
	resource := cdsReply.GetResources()[0]
	cluster := &v3clusterpb.Cluster{}
	if err := proto.Unmarshal(resource.GetValue(), cluster); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cluster resource from CDS response: %v", err)
	}
	if cluster.GetName() != expectedClusterName {
		return nil, fmt.Errorf("cluster resource name |%v| does not match |%v|", cluster.GetName(), expectedClusterName)
	}
	return cluster, nil
}

// Extract primary cluster (for DirectPath) and secondary cluster (for fallback to CFE) from aggregate cluster
func processAggregateClusterResponse(cdsReply *v3discoverypb.DiscoveryResponse, clusterName string) ([]string, error) {
	aggregateCluster, err := getCluster(cdsReply, clusterName)
	if err != nil {
		return []string{}, fmt.Errorf("failed to get aggregate cluster from CDS response: %v", err)
	}
	if aggregateCluster.GetClusterType() == nil || aggregateCluster.GetClusterType().GetName() != "envoy.clusters.aggregate" {
		return []string{}, fmt.Errorf("failed to receive an aggregate cluster from Traffic Director, set --xds_expect_fallback_configured=false if CFE fallback has been intentionally disabled for this service")
	}
	clusterConfig := &v3clusterextpb.ClusterConfig{}
	if err := proto.Unmarshal(aggregateCluster.GetClusterType().GetTypedConfig().GetValue(), clusterConfig); err != nil {
		return []string{}, fmt.Errorf("failed to unmarshal cluster_config resource from CDS response: %v", err)
	}
	if len(clusterConfig.GetClusters()) == 0 {
		return []string{}, fmt.Errorf("no clusters received in aggregate cluster")
	}
	if len(clusterConfig.GetClusters()) != 2 {
		for _, c := range clusterConfig.GetClusters() {
			infoLog.Printf("Found cluster in aggregate cluster: |%v|", c)
		}
		return []string{}, fmt.Errorf("expected to receive 2 clusters in aggregate cluster, but received %v", len(clusterConfig.GetClusters()))
	}
	return clusterConfig.GetClusters(), nil
}

// Extract service_name from EDS cluster
func processEdsClusterResponse(cdsReply *v3discoverypb.DiscoveryResponse, clusterName string) (string, error) {
	edsCluster, err := getCluster(cdsReply, clusterName)
	if err != nil {
		return "", fmt.Errorf("failed to get EDS cluster from CDS response: %v", err)
	}
	if edsCluster.GetType() != v3clusterpb.Cluster_EDS {
		return "", fmt.Errorf("the cluster type is expected to be EDS, but it is: %v, set --xds_expect_fallback_configured=true if CFE fallback is expected to be configured for this service", edsCluster.GetType())
	}
	// The cluster lbPolicy field must be Round Robin or Ring Hash
	if edsCluster.GetLbPolicy() != v3clusterpb.Cluster_ROUND_ROBIN && edsCluster.GetLbPolicy() != v3clusterpb.Cluster_RING_HASH {
		return "", fmt.Errorf("expected cluster lb_policy field to be Round Robin or Ring Hash, but is is: |%+v|", edsCluster.GetLbPolicy())
	}
	if serviceName := edsCluster.GetEdsClusterConfig().GetServiceName(); serviceName != "" {
		infoLog.Printf("eds_cluster_config.service_name |%v| is not empty, use it as the service_name for EDS request", serviceName)
		return serviceName, nil
	}
	infoLog.Printf("eds_cluster_config.service_name is empty, use cluster_name |%v| as the service_name for EDS request", clusterName)
	return clusterName, nil
}

// Check DNS cluster
func processDNSClusterResponse(cdsReply *v3discoverypb.DiscoveryResponse, clusterName string) error {
	dnsCluster, err := getCluster(cdsReply, clusterName)
	if err != nil {
		return fmt.Errorf("failed to get DNS cluster from CDS response: %v", err)
	}
	// cluster type must be LOGICAL_DNS
	if dnsCluster.GetType() != v3clusterpb.Cluster_LOGICAL_DNS {
		return fmt.Errorf("the cluster type is expected to be LOGICAL_DNS, but it is: %v", dnsCluster.GetType())
	}
	// the DNS cluster must exactly have one locality
	if len(dnsCluster.GetLoadAssignment().GetEndpoints()) != 1 {
		for _, locality := range dnsCluster.GetLoadAssignment().GetEndpoints() {
			infoLog.Printf("Found locality in DNS cluster: %v", locality)
		}
		return fmt.Errorf("the DNS cluster must have exactly 1 locality, but it has %v", len(dnsCluster.GetLoadAssignment().GetEndpoints()))
	}
	// the locality must exactly have one endpoint
	locality := dnsCluster.GetLoadAssignment().GetEndpoints()[0]
	if len(locality.GetLbEndpoints()) != 1 {
		for _, endpoint := range locality.GetLbEndpoints() {
			infoLog.Printf("Found endpoint in DNS cluster: %v", endpoint)
		}
		return fmt.Errorf("the DNS cluster must exactly has 1 endpoint, but it has %v", len(locality.GetLbEndpoints()))
	}
	// check socket_address field of the endpoint
	socketAddress := locality.GetLbEndpoints()[0].GetEndpoint().GetAddress().GetSocketAddress()
	if socketAddress.GetAddress() != *service {
		return fmt.Errorf("the address field must be service name |%v|, but it is |%v|", *service, socketAddress.GetAddress())
	}
	if socketAddress.GetPortValue() != 443 {
		return fmt.Errorf("the port_value field must be CFE port 443, but it is: %v", socketAddress.GetPortValue())
	}
	if socketAddress.GetResolverName() != "" {
		return fmt.Errorf("the resolver_name field must not be set, but it is: %v", socketAddress.GetResolverName())
	}
	return nil
}

// Extract backend IP:port from RDS response
func processEdsResponse(edsReply *v3discoverypb.DiscoveryResponse) ([]string, error) {
	if len(edsReply.GetResources()) != 1 {
		if len(edsReply.GetResources()) == 0 {
			return []string{}, fmt.Errorf("no cluster_load_assignment resource received in EDS response")
		}
		return []string{}, fmt.Errorf("expect to receive only 1 cluster_load_assigment resource in EDS response, but received %v", len(edsReply.GetResources()))
	}
	resource := edsReply.GetResources()[0]
	clusterLoadAssignment := &v3endpointpb.ClusterLoadAssignment{}
	if err := proto.Unmarshal(resource.GetValue(), clusterLoadAssignment); err != nil {
		return []string{}, fmt.Errorf("failed to unmarshal cluster_load_assigement resource from EDS response: %v", err)
	}
	var results []string
	countPriorityZero, countPriorityOne, countPriorityOthers := 0, 0, 0
	numBackendInPriorityZero, numBackendInPriorityOne := 0, 0
	for _, endpoint := range clusterLoadAssignment.GetEndpoints() {
		switch endpoint.GetPriority() {
		case 0:
			countPriorityZero++
			numBackendInPriorityZero += len(endpoint.GetLbEndpoints())
			for _, lbendpoint := range endpoint.GetLbEndpoints() {
				endpoint := lbendpoint.GetEndpoint().GetAddress().GetSocketAddress()
				results = append(results, net.JoinHostPort(endpoint.GetAddress(), fmt.Sprint(endpoint.GetPortValue())))
			}
		case 1:
			countPriorityOne++
			numBackendInPriorityOne += len(endpoint.GetLbEndpoints())
		default:
			countPriorityOthers++
		}
	}
	if countPriorityZero == 0 {
		return []string{}, fmt.Errorf("expected to receive at least 1 endpoint with priority 0, but received %v", countPriorityZero)
	}
	if countPriorityOthers != 0 {
		return []string{}, fmt.Errorf("received endpoint whose priority is not 0 or 1")
	}
	if results == nil {
		return []string{}, fmt.Errorf("no endpoints received in EDS response")
	}
	infoLog.Printf("Received %v backends in the primary cluster", numBackendInPriorityZero)
	infoLog.Printf("Received %v backends in the secondary cluster", numBackendInPriorityOne)
	return results, nil
}

func newNode(zone string, ipv6Capable bool) *v3corepb.Node {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		infoLog.Printf("failed to create random token: %v, node ID will not be unique", err)
	}
	var id strings.Builder
	fmt.Fprintf(&id, "dp-check-xds-%d", binary.LittleEndian.Uint64(r[:]))
	infoLog.Printf("ADS stream will use node ID: %s", id.String())
	ret := &v3corepb.Node{
		Id:                   id.String(),
		UserAgentName:        userAgentName,
		UserAgentVersionType: &v3corepb.Node_UserAgentVersion{UserAgentVersion: userAgentVersion},
		ClientFeatures:       []string{clientFeatureNoOverprovisioning},
	}
	ret.Locality = &v3corepb.Locality{Zone: zone}
	if ipv6Capable {
		ret.Metadata = &structpb.Struct{
			Fields: map[string]*structpb.Value{
				ipv6CapableMetadataName: structpb.NewBoolValue(true),
			},
		}
	}
	return ret
}

func getZone(timeout time.Duration) (string, error) {
	qualifiedZone, err := getFromMetadata(timeout, zoneURL)
	if err != nil {
		return "", fmt.Errorf("could not fetch zone from metadata server: |%v|", err)
	}
	i := bytes.LastIndexByte(qualifiedZone, '/')
	if i == -1 {
		return "", fmt.Errorf("could not parse zone |%v|", qualifiedZone)
	}
	return string(qualifiedZone[i+1:]), nil
}

func getFromMetadata(timeout time.Duration, urlStr string) ([]byte, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: timeout}
	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: http.Header{"Metadata-Flavor": {"Google"}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed communicating with metadata server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata server returned resp with non-OK: %v", resp)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading from metadata server: %v", err)
	}
	return body, nil
}

func checkLDS(stream adsStream, node *v3corepb.Node, versionInfoMap, nonceMap map[string]string) (string, error) {
	ldsReply, err := sendXdsRequest(stream, node, V3ListenerURL, *service, versionInfoMap, nonceMap)
	if err != nil {
		return "", fmt.Errorf("fail to send LDS request: %v", err)
	}
	clusterName, err := processLdsResponse(ldsReply)
	if err != nil {
		return "", fmt.Errorf("fail to process LDS response: %v", err)
	}
	infoLog.Printf("Successfully extract cluster_name from LDS response: |%+v|", clusterName)
	return clusterName, nil
}

func checkCDS(stream adsStream, node *v3corepb.Node, clusterName string, versionInfoMap, nonceMap map[string]string) (string, error) {
	// check aggregate cluster
	cdsReply, err := sendXdsRequest(stream, node, V3ClusterURL, clusterName, versionInfoMap, nonceMap)
	if err != nil {
		return "", fmt.Errorf("fail to send CDS request: %v", err)
	}
	var edsClusterName string
	var edsClusterReply *v3discoverypb.DiscoveryResponse
	if *xdsExpectFallbackConfigured {
		clusters, err := processAggregateClusterResponse(cdsReply, clusterName)
		if err != nil {
			return "", fmt.Errorf("fail to process aggregate cluster response: %v", err)
		}
		infoLog.Printf("Received primary cluster for DirectPath: %v", clusters[0])
		infoLog.Printf("Received secondary cluster for fallback to CFE: %v", clusters[1])
		// check primary cluster
		var edsClusterErr error
		edsClusterName = clusters[0]
		edsClusterReply, edsClusterErr = sendXdsRequest(stream, node, V3ClusterURL, edsClusterName, versionInfoMap, nonceMap)
		if edsClusterErr != nil {
			return "", fmt.Errorf("fail to send EDS cluster request: %v", err)
		}
		// check secondary cluster
		dnsClusterReply, err := sendXdsRequest(stream, node, V3ClusterURL, clusters[1], versionInfoMap, nonceMap)
		if err != nil {
			return "", fmt.Errorf("fail to send DNS cluster request: %v", err)
		}
		if err = processDNSClusterResponse(dnsClusterReply, clusters[1]); err != nil {
			return "", fmt.Errorf("fail to process DNS cluster response: %v", err)
		}
	} else {
		edsClusterName = clusterName
		edsClusterReply = cdsReply
	}
	serviceName, err := processEdsClusterResponse(edsClusterReply, edsClusterName)
	if err != nil {
		return "", fmt.Errorf("fail to process EDS cluster response: %v", err)
	}
	infoLog.Printf("Successfully extract service_name from CDS response: |%v|", serviceName)
	return serviceName, nil
}

func checkEDS(stream adsStream, node *v3corepb.Node, serviceName string, versionInfoMap, nonceMap map[string]string) ([]string, error) {
	edsReply, err := sendXdsRequest(stream, node, V3EndpointsURL, serviceName, versionInfoMap, nonceMap)
	if err != nil {
		return []string{}, fmt.Errorf("fail to send EDS request: %v", err)
	}
	xdsBackendAddrs, err := processEdsResponse(edsReply)
	if err != nil {
		return []string{}, fmt.Errorf("fail to process EDS response: %v", err)
	}
	if len(xdsBackendAddrs) == 0 {
		return []string{}, fmt.Errorf("no backend addresses received in EDS response: %v", err)
	}
	return xdsBackendAddrs, nil
}

func getBackendAddrsFromTrafficDirector(ipv6Capable bool) ([]string, error) {
	// Open a RPC stream to Traffic Director
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	stream, err := openAdsStream(ctx)
	if err != nil {
		return []string{}, fmt.Errorf("failed to open stream to Traffic Director: %v", err)
	}
	// Create node
	zone, err := getZone(10 * time.Second)
	if err != nil {
		return []string{}, fmt.Errorf("failed to get zone from metadata server: %v", err)
	}
	node := newNode(zone, ipv6Capable)
	// XDS
	versionInfoMap := map[string]string{
		V3ListenerURL:    "",
		V3RouteConfigURL: "",
		V3ClusterURL:     "",
		V3EndpointsURL:   "",
	}
	nonceMap := map[string]string{
		V3ListenerURL:    "",
		V3RouteConfigURL: "",
		V3ClusterURL:     "",
		V3EndpointsURL:   "",
	}
	// LDS
	clusterName, err := checkLDS(stream, node, versionInfoMap, nonceMap)
	if err != nil {
		return []string{}, fmt.Errorf("LDS failed: %v", err)
	}
	// CDS
	serviceName, err := checkCDS(stream, node, clusterName, versionInfoMap, nonceMap)
	if err != nil {
		return []string{}, fmt.Errorf("CDS failed: %v", err)
	}
	// EDS
	xdsBackendAddrs, err := checkEDS(stream, node, serviceName, versionInfoMap, nonceMap)
	if err != nil {
		return []string{}, fmt.Errorf("EDS failed: %v", err)
	}
	var ipVersion string
	if ipv6Capable {
		ipVersion = "IPv6"
	} else {
		ipVersion = "IPv4"
	}
	for _, backend := range xdsBackendAddrs {
		infoLog.Printf("Found %v backend address from Traffic Director: |%v|", ipVersion, backend)
	}
	return xdsBackendAddrs, nil
}

func maybeOverrideFlags() {
	const spannerSuffix = "spanner.googleapis.com"
	if strings.HasSuffix(spannerSuffix, *service) {
		// expect fallback configured for .*spanner.googleapis.com
		infoLog.Printf("overriding flag --xds_expect_fallback_configured to true because --service ends with %s, previous setting: %v", spannerSuffix, *xdsExpectFallbackConfigured)
		*xdsExpectFallbackConfigured = true
	}
}

func main() {
	flag.Parse()
	infoLog.Printf("Running dp_check: service=%s, ipv4_only=%v, ipv6_only=%v, ipv4_and_v6=%v, check_grpclb=%v, check_xds=%v, td_endpoint=%s, xds_expect_fallback_configured=%v\n", *service, *ipv4Only, *ipv6Only, *ipv4AndV6, *checkGrpclb, *checkXds, *trafficDirectorHostname, *xdsExpectFallbackConfigured)
	maybeOverrideFlags()
	if len(*service) == 0 {
		panic("--service not set")
	}
	var skipIPv6Err error
	var skipIPv4Err error
	explicitChecks := 0
	if *ipv4Only {
		skipIPv6Err = fmt.Errorf("skip IPv6 checks because of flag: --ipv4_only")
		explicitChecks++
	}
	if *ipv6Only {
		skipIPv4Err = fmt.Errorf("skip IPv4 checks because of flag: --ipv6_only")
		explicitChecks++
	}
	if *ipv4AndV6 {
		explicitChecks++
	}
	if explicitChecks > 1 {
		infoLog.Printf("At most one of --ipv4_only, --ipv6_only, or --ipv4_and_v6 can be set. Have --ipv4_only=%v --ipv6_only=%v --ipv4_and_v6=%v.", *ipv4Only, *ipv6Only, *ipv4AndV6)
		os.Exit(1)
	}
	var skipGrpclbErr error
	if !*checkGrpclb {
		skipGrpclbErr = fmt.Errorf("skip grpclb related checks because --check_grpclb is false")
	}
	var skipXdsErr error
	if !*checkXds {
		skipXdsErr = fmt.Errorf("skip xds related checks because --check_xds is false")
	}
	var balancerHostname string
	var balancerPort string
	if len(*balancerTargetOverride) > 0 {
		infoLog.Printf("--balancer_target_override is non-empty. Will override load balancer target used in load balancer connectivity checks and queries to: %v", *balancerTargetOverride)
		var err error
		if balancerHostname, balancerPort, err = net.SplitHostPort(*balancerTargetOverride); err != nil {
			infoLog.Printf("ERROR: --balancer_target_override was set to %v, but failed to split into host and port: %v", *balancerTargetOverride, err)
			os.Exit(1)
		}
		if net.ParseIP(balancerHostname) != nil {
			infoLog.Printf("ERROR: --balancer_target_override was set to %v, but this flag does not support IP literal based addresses, the host must be a DNS hostname", *balancerTargetOverride)
			os.Exit(1)
		}
	}
	if syscall.Getuid() != 0 {
		infoLog.Println("Not running as root, some checks may fail.")
	}

	// Check if dp_check is running on GCP
	runCheck("Running on GCP", func() error {
		ret, err := isRunningOnGCP()
		if err != nil {
			return err
		}
		if !ret {
			return fmt.Errorf("dp_check is not running on GCP, this tool will not work as intended")
		}
		return nil
	})

	var ipv6FromMetadataServer *net.IP
	runCheck("IPv6 address allocated to VM's primary NIC (i.e. DirectPath IPv6 enablement)", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		var err error
		ipv6FromMetadataServer, err = fetchIPFromMetadataServer("IPv6")
		return err
	})
	var ipv4FromMetadataServer *net.IP
	runCheck("IPv4 address allocated to VM's primary NIC", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		var err error
		ipv4FromMetadataServer, err = fetchIPFromMetadataServer("IPv4")
		return err
	})

	// Check if xds bootstrap environment variable is set
	runCheck("Xds bootstrap environment variable", func() error {
		if skipXdsErr != nil {
			return &skipCheckError{err: skipXdsErr}
		}
		const xdsBootStrapEnvVar = "GRPC_XDS_BOOTSTRAP"
		const xdsBootStrapConfigEnvVar = "GRPC_XDS_BOOTSTRAP_CONFIG"
		if os.Getenv(xdsBootStrapEnvVar) != "" || os.Getenv(xdsBootStrapConfigEnvVar) != "" {
			return fmt.Errorf("DirectPath can not be used with environment variables |%v| or |%v|", xdsBootStrapEnvVar, xdsBootStrapConfigEnvVar)
		}
		return nil
	})

	// Check DNS
	srvQueriesSucceeded := false
	runCheck("Service SRV DNS queries", func() error {
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		infoLog.Printf("Lookup service SRV records with:|net.DefaultResolver.LoookupSRV(context.Background(), \"grpclb\", \"tcp\", \"%v\")|...", *service)
		_, srvs, err := net.DefaultResolver.LookupSRV(context.Background(), "grpclb", "tcp", *service)
		if err != nil || len(srvs) == 0 {
			if ipv6FromMetadataServer == nil {
				return fmt.Errorf(`SRV record resolution for _grpclb._tcp.%s failed with error:|%v|.
This is expected (even if %s is a DirectPath-enabled service) because this VM is not DirectPath-enabled`, *service, err, *service)
			}
			return fmt.Errorf(`SRV record resolution for _grpclb._tcp.%s failed with error:|%v|.
Because this VM is known to be DirectPath-enabled, there are three possible causes:
a) %s is not a DirectPath-enabled service
b) The query was rejected because some attribute(s) of this specific VM (for example the VPC network project number of this VM's primary network interface, the VM project number, or the current region or zone we're running in), are causing this VM to be prevented DirectPath access to %s.
c) Something is broken i.e. there is a serious bug somewhere.

See results of LB query below which may give help in diagnosing which case we fall into.`, *service, err, *service)
		}
		if len(srvs) != 1 {
			return fmt.Errorf("Got %d SRV records:|%v|. This is not necessarily an error but is unexpected", len(srvs), srvs)
		}
		if strings.Compare(srvs[0].Target, loadBalancerIPv6OnlyDNS) != 0 && strings.Compare(srvs[0].Target, loadBalancerDualstackDNS) != 0 {
			return fmt.Errorf("Got SRV record target:|%v|; expected:|%v| or |%v|", srvs[0].Target, loadBalancerIPv6OnlyDNS, loadBalancerDualstackDNS)
		}
		if len(*balancerTargetOverride) == 0 {
			balancerHostname = srvs[0].Target
			if balancerHostname == loadBalancerIPv6OnlyDNS && explicitChecks == 0 && !*checkXds {
				skipIPv4Err = fmt.Errorf("%v was detected to be an IPv6-only service because it's DirectPath SRV record pointed to: %v, so DirectPath/IPv4 does not need to work from this VM. Set the flag --ipv4_and_v6 if you want to run this check anyways", *service, loadBalancerIPv6OnlyDNS)
			}
			balancerPort = strconv.Itoa(int(srvs[0].Port))
			infoLog.Println("--balancer_target_override is empty. Will use results from SRV record for the load balancer target used in load balancer connectivity checks and queries")
		}
		infoLog.Printf("Determined load balancer hostname:|%v| and port:|%v|", balancerHostname, balancerPort)
		srvQueriesSucceeded = true
		return nil
	})
	if len(balancerHostname) == 0 {
		balancerHostname = loadBalancerDualstackDNS
		infoLog.Printf("SRV query for _grpclb._tcp.%s failed and --balancer_target_override is unset. Assuming (possible incorrectly) that the load balancer's hostname is %s", *service, balancerHostname)
	}
	if len(balancerPort) == 0 {
		balancerPort = strconv.Itoa(defaultLoadBalancerPort)
		infoLog.Printf("SRV query for _grpclb._tcp.%s failed and --balancer_target_override is unset. Assuming (possible incorrectly) that the load balancer's port is %s", *service, balancerPort)
	}
	var ipv6BalancerIPs []net.IP
	runCheck("Load balancer IPv6 DNS queries", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		var err error
		infoLog.Printf("Resolve LB IPv6 addrs with:|new(net.Resolver).LookupIP(context.Background(), \"ip6\", \"%v\")|...", balancerHostname)
		if ipv6BalancerIPs, err = new(net.Resolver).LookupIP(context.Background(), "ip6", balancerHostname); len(ipv6BalancerIPs) == 0 || err != nil {
			return fmt.Errorf(`DNS resolution of load balancer IPv6 addresses failed: %v.
This is unexpected for both IPv6-only and dualstack DirectPath services. Either this VM doesn't have DirectPath access, or there is a bug that may be causing a larger outage`, err)
		}
		for _, addr := range ipv6BalancerIPs {
			infoLog.Printf("Resolved LB IPv6 addr: %v", addr.String())
		}
		return nil
	})
	var ipv4BalancerIPs []net.IP
	runCheck("Load balancer IPv4 DNS queries", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		var err error
		infoLog.Printf("Resolve LB IPv6 addrs with:|new(net.Resolver).LookupIP(context.Background(), \"ip4\", \"%v\")|...", balancerHostname)
		ipv4BalancerIPs, err = new(net.Resolver).LookupIP(context.Background(), "ip4", balancerHostname)
		// Fail this check if either:
		// a) we expect to resolve LB IPv4 endpoints but don't
		// b) we don't expect to resolve LB IPv4 endpoint but do
		if strings.Compare(balancerHostname, loadBalancerDualstackDNS) == 0 {
			if len(ipv4BalancerIPs) == 0 || err != nil {
				return fmt.Errorf(`DNS resolution of load balancer IPv4 addresses failed: %v.
This is unexpected for dualstack DirectPath services. Either this VM doesn't have DirectPath access, or there is a bug that may be causing a larger outage`, err)
			}
			for _, addr := range ipv4BalancerIPs {
				infoLog.Printf("Resolved LB IPv4 addr: %v", addr.String())
			}
		} else {
			if len(ipv4BalancerIPs) > 0 {
				return fmt.Errorf(`the DNS resolution of load balancer IPv4 addresses succeeded, but %v is not expected
to be a dualstack service because we resolver load balancer hostname:|%v| which does not match the dualstack load balancer hostname:|%v|,
this indicates a possible bug that may be causing a larger outage`, balancerHostname, loadBalancerDualstackDNS, *service)
			}
		}
		return nil
	})

	var directPathIPv6NetworkInterface *net.Interface
	runCheck("Local IPv6 addresses", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		var err error
		directPathIPv6NetworkInterface, err = checkLocalIPv6Addresses(ipv6FromMetadataServer)
		return err
	})
	runCheck("Local IPv6 loopback address", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		return checkLocalIPv6LoopbackAddress(ipv6FromMetadataServer)
	})
	var directPathIPv4NetworkInterface *net.Interface
	runCheck("Local IPv4 addresses", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		var err error
		directPathIPv4NetworkInterface, err = checkLocalIPv4Addresses(ipv4FromMetadataServer)
		return err
	})
	runCheck("Local IPv6 routes", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		return checkLocalIPv6Routes(directPathIPv6NetworkInterface)
	})
	runCheck("Local IPv4 routes", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		return checkLocalIPv4Routes(directPathIPv4NetworkInterface, ipv4FromMetadataServer, []net.IP{net.IPv4(34, 126, 0, 0)}, "1")
	})

	// Contact LBs
	tcpOverIPv6ToLoadBalancersSucceeded := false
	runCheck("TCP/IPv6 connectivity to load balancers", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if len(ipv6BalancerIPs) == 0 {
			return fmt.Errorf("skipping \"TCP/IPv6 connectivity to load balancers\" because prior DNS resolution of LB IPv6 address failed")
		}
		addr := net.JoinHostPort(ipv6BalancerIPs[0].String(), balancerPort)
		infoLog.Printf("Check TCP/IPv6 connectivity to LB's with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...", addr)
		if _, err := net.DialTimeout("tcp", addr, time.Second*5); err != nil {
			return fmt.Errorf("TCP/IPv6 connectivity to the load balancer failed: %v. This may be a transient error specific to the load balancer at %v", err, addr)
		}
		tcpOverIPv6ToLoadBalancersSucceeded = true
		return nil
	})
	tcpOverIPv4ToLoadBalancersSucceeded := false
	runCheck("TCP/IPv4 connectivity to load balancers", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if len(ipv4BalancerIPs) == 0 {
			return fmt.Errorf("skipping \"TCP/IPv4 connectivity to load balancers\" because prior DNS resolution of LB IPv4 address failed")
		}
		addr := net.JoinHostPort(ipv4BalancerIPs[0].String(), balancerPort)
		infoLog.Printf("Check TCP/IPv4 connectivity to LB's with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...", addr)
		if _, err := net.DialTimeout("tcp", addr, time.Second*5); err != nil {
			return fmt.Errorf("TCP/IPv4 connectivity to the load balancer failed: %v. This may be a transient error specific to the load balancer at %v", err, addr)
		}
		tcpOverIPv4ToLoadBalancersSucceeded = true
		return nil
	})

	// Resolve backends
	ipv6BackendAddrs := maybeInitBackendAddrsFromFlags(net.IPv6len)
	runCheck("Discovery of IPv6 backends via load balancers", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if !tcpOverIPv6ToLoadBalancersSucceeded {
			return fmt.Errorf("skipping discovery of backends via load balancers because TCP connectivity to LBs failed")
		}
		var err error
		ipv6BackendAddrs, err = resolveBackends(net.JoinHostPort(ipv6BalancerIPs[0].String(), balancerPort), balancerHostname, srvQueriesSucceeded)
		return err
	})
	ipv4BackendAddrs := maybeInitBackendAddrsFromFlags(net.IPv4len)
	runCheck("Discovery of IPv4 backends via load balancers", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if !tcpOverIPv4ToLoadBalancersSucceeded {
			return fmt.Errorf("skipping discovery of backends via load balancers because TCP connectivity to LBs failed")
		}
		var err error
		ipv4BackendAddrs, err = resolveBackends(net.JoinHostPort(ipv4BalancerIPs[0].String(), balancerPort), balancerHostname, srvQueriesSucceeded)
		return err
	})

	// Contact backends
	tcpConnectivityToIpv6BackendSucceeded := false
	runCheck("TCP connectivity to IPv6 backends", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if len(ipv6BackendAddrs) == 0 {
			return fmt.Errorf("skipping TCP connectivity to IPv6 backends because discovery of IPv6 backends failed")
		}
		infoLog.Printf("Check TCP connectivity to IPv6 backends with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...", ipv6BackendAddrs[0])
		if _, err := net.DialTimeout("tcp", ipv6BackendAddrs[0], time.Second*5); err != nil {
			return fmt.Errorf("TCP connectivity to backend addr - %v failed: %v", ipv6BackendAddrs[0], err)
		}
		tcpConnectivityToIpv6BackendSucceeded = true
		return nil
	})
	tcpConnectivityToIpv4BackendSucceeded := false
	runCheck("TCP connectivity to IPv4 backends", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if len(ipv4BackendAddrs) == 0 {
			return fmt.Errorf("skipping TCP connectivity to IPv4 backends because discovery of IPv4 backends failed")
		}
		infoLog.Printf("Check TCP connectivity to IPv4 backends with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...", ipv4BackendAddrs[0])
		if _, err := net.DialTimeout("tcp", ipv4BackendAddrs[0], time.Second*5); err != nil {
			return fmt.Errorf("TCP connectivity to backend addr - %v failed: %v", ipv4BackendAddrs[0], err)
		}
		tcpConnectivityToIpv4BackendSucceeded = true
		return nil
	})
	runCheck("Secure connectivity to IPv6 backends", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if !tcpConnectivityToIpv6BackendSucceeded {
			return fmt.Errorf("skipping secure connectivity to IPv6 backends because TCP connectivity to IPv6 backends did not succeed")
		}
		infoLog.Println("Check secure connectivity to IPv6 backends by attempting to complete all handshakes involved in the setup of a gRPC/ALTS connection to", ipv6BackendAddrs[0])
		return checkSecureConnectivityToBackend(ipv6BackendAddrs[0])
	})
	runCheck("Secure connectivity to IPv4 backends", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if skipGrpclbErr != nil {
			return &skipCheckError{err: skipGrpclbErr}
		}
		if !tcpConnectivityToIpv4BackendSucceeded {
			return fmt.Errorf("skipping secure connectivity to IPv4 backends because TCP connectivity to IPv4 backends did not succeed")
		}
		infoLog.Println("Check secure connectivity to IPv4 backends by attempting to complete all handshakes involved in the setup of a gRPC/ALTS connection to", ipv4BackendAddrs[0])
		return checkSecureConnectivityToBackend(ipv4BackendAddrs[0])
	})

	// xds
	var xdsIPv6BackendAddrs []string
	runCheck("Get IPv6 backend addresses from Traffic Director", func() error {
		if skipXdsErr != nil {
			return &skipCheckError{err: skipXdsErr}
		}
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		var err error
		xdsIPv6BackendAddrs, err = getBackendAddrsFromTrafficDirector(true)
		return err
	})

	var xdsIPv4BackendAddrs []string
	runCheck("Get IPv4 backend addresses from Traffic Director", func() error {
		if skipXdsErr != nil {
			return &skipCheckError{err: skipXdsErr}
		}
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		var err error
		xdsIPv4BackendAddrs, err = getBackendAddrsFromTrafficDirector(false)
		return err
	})

	xdsTCPConnectivityToIpv6BackendSucceeded := false
	runCheck("TCP connectivity to IPv6 backends from Traffic Director", func() error {
		if skipXdsErr != nil {
			return &skipCheckError{err: skipXdsErr}
		}
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if len(xdsIPv6BackendAddrs) == 0 {
			return fmt.Errorf("skipping TCP connectivity to IPv6 backends because discovery of IPv6 backends failed")
		}
		infoLog.Printf("Check TCP connectivity to IPv6 backends with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...", xdsIPv6BackendAddrs[0])
		if _, err := net.DialTimeout("tcp", xdsIPv6BackendAddrs[0], time.Second*5); err != nil {
			return fmt.Errorf("TCP connectivity to backend addr - %v failed: %v", xdsIPv6BackendAddrs[0], err)
		}
		xdsTCPConnectivityToIpv6BackendSucceeded = true
		return nil
	})

	xdsTCPConnectivityToIpv4BackendSucceeded := false
	runCheck("TCP connectivity to IPv4 backends from Traffic Director", func() error {
		if skipXdsErr != nil {
			return &skipCheckError{err: skipXdsErr}
		}
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if len(xdsIPv4BackendAddrs) == 0 {
			return fmt.Errorf("skipping TCP connectivity to IPv4 backends because discovery of IPv4 backends failed")
		}
		infoLog.Printf("Check TCP connectivity to IPv4 backends with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...", xdsIPv4BackendAddrs[0])
		if _, err := net.DialTimeout("tcp", xdsIPv4BackendAddrs[0], time.Second*5); err != nil {
			return fmt.Errorf("TCP connectivity to backend addr - %v failed: %v", xdsIPv4BackendAddrs[0], err)
		}
		xdsTCPConnectivityToIpv4BackendSucceeded = true
		return nil
	})

	runCheck("Secure connectivity to IPv6 backends from Traffic Director", func() error {
		if skipXdsErr != nil {
			return &skipCheckError{err: skipXdsErr}
		}
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if !xdsTCPConnectivityToIpv6BackendSucceeded {
			return fmt.Errorf("skipping secure connectivity to IPv6 backends because TCP connectivity to IPv6 backends did not succeed")
		}
		infoLog.Println("Check secure connectivity to IPv6 backends by attempting to complete all handshakes involved in the setup of a gRPC/ALTS connection to", xdsIPv6BackendAddrs[0])
		return checkSecureConnectivityToBackend(xdsIPv6BackendAddrs[0])
	})

	runCheck("Secure connectivity to IPv4 backends from Traffic Director", func() error {
		if skipXdsErr != nil {
			return &skipCheckError{err: skipXdsErr}
		}
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if !xdsTCPConnectivityToIpv4BackendSucceeded {
			return fmt.Errorf("skipping secure connectivity to IPv4 backends because TCP connectivity to IPv4 backends did not succeed")
		}
		infoLog.Println("Check secure connectivity to IPv4 backends by attempting to complete all handshakes involved in the setup of a gRPC/ALTS connection to", xdsIPv4BackendAddrs[0])
		return checkSecureConnectivityToBackend(xdsIPv4BackendAddrs[0])
	})

	os.Exit(failureCount)
}
