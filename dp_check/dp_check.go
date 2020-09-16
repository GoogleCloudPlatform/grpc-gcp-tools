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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	lbpb "google.golang.org/grpc/balancer/grpclb/grpc_lb_v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/alts"
	"google.golang.org/grpc/status"
)

var (
	service  = flag.String("service", "", "Required. The public DirectPath-enabled DNS of the service to check")
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
	balancerTargetOverride = flag.String("balancer_target_override", "", `Optional. The target hostname (or IP literal), including
port number, of the load balancer. This is mainly useful if one would like to check the proper setup of a VM and service with respect
to e.g. DirectPath networking and load balancing, in such a way that ignores DNS. In most use cases, it would be desirable to set this
in conjunction with --skip="Load balancer DNS queries,Service SRV DNS queries"`)
	userAgent    = flag.String("user_agent", "", "Optional. The user agent header to use on RPCs to the load balancer")
	infoLog      = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	failureCount int
	runningOS    = runtime.GOOS
)

type platformError string

func (k platformError) Error() string {
	return fmt.Sprintf("%s is not supported", string(k))
}

const (
	loadBalancerIPv6OnlyDNS  = "grpclb.directpath.google.internal."
	loadBalancerDualstackDNS = "grpclb-dualstack.directpath.google.internal."
	defaultLoadBalancerPort  = 9355
	linuxProductNameFile     = "/sys/class/dmi/id/product_name"
	windowsManufacturerRegex = ":(.*)"
	windowsCheckCommand      = "powershell.exe"
	windowsCheckCommandArgs  = "Get-WmiObject -Class Win32_BIOS"
	powershellOutputFilter   = "Manufacturer"
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

func findLocalAddress(ipMatches func(net.IP) bool) (*net.Interface, error) {
	infoLog.Println("Check local addresses by iterating over all ip addresses from interfaces returned by: |net.Interfaces()|")
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var match net.Interface
	foundMatch := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp != net.FlagUp {
			continue
		}
		infoLog.Printf("Checking non-loopback and up network interface: |Name: %s, hardware address: %s, flags: %s|", iface.Name, iface.HardwareAddr, iface.Flags)
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
		return nil, fmt.Errorf("Skipping search for DirectPath-capable IPv6 address because the VM failed to get a valid IPv6 address from metadata server")
	}
	var err error
	var iface *net.Interface
	if iface, err = findLocalAddress(func(ip net.IP) bool { return ip.To4() == nil && ip.Equal(*ipv6FromMetadataServer) }); err != nil {
		return nil, fmt.Errorf("Failed to find local DirectPath-capable IPv6 address: %v. This VM was expected to have a network interface with IPv6 address: %s assigned to it, but no such interface was found, it's likely that IPv6 DHCP setup either failed or hasn't been attempted", err, ipv6FromMetadataServer)
	}
	return iface, nil
}

func checkLocalIPv4Addresses(ipv4FromMetadataServer *net.IP) (*net.Interface, error) {
	if ipv4FromMetadataServer == nil {
		return nil, fmt.Errorf("Skipping search for DirectPath-capable IPv4 address because the VM failed to get a valid IPv4 address from metadata server")
	}
	var err error
	var iface *net.Interface
	if iface, err = findLocalAddress(func(ip net.IP) bool { return ip.To4() != nil && ip.Equal(*ipv4FromMetadataServer) }); err != nil {
		return nil, fmt.Errorf("Failed to find local DirectPath-capable IPv4 address: %v. This VM was expected to have a network interface with IPv4 address: %s assigned to it, but no such interface was found", err, ipv4FromMetadataServer)
	}
	return iface, nil
}

func findLocalRoute(iface net.Interface, addrFamily int, routeMatches func(netlink.Route) bool) error {
	var addrFamilyStr string
	if addrFamily == netlink.FAMILY_V4 {
		addrFamilyStr = "IPv4"
	} else if addrFamily == netlink.FAMILY_V6 {
		addrFamilyStr = "IPv6"
	} else {
		return fmt.Errorf("Invalid address family %v is not IPv4 or IPv6", addrFamily)
	}
	infoLog.Printf("Check all %v routes on network interface |Name: %s, hardware address: %s, flags: %s| returned by |netlink.LinkByName(%s)|", addrFamilyStr, iface.Name, iface.HardwareAddr, iface.Flags, iface.Name)
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}
	rl, err := netlink.RouteList(link, addrFamily)
	if err != nil {
		return fmt.Errorf("\"RouteList(link, addrFamily)\" failed: %v", err)
	}
	foundMatch := false
	for _, r := range rl {
		infoLog.Printf("Found %v route: |%s| on network interface |%s|", addrFamily, r, iface.Name)
		if routeMatches(r) {
			foundMatch = true
		}
	}
	if !foundMatch {
		return fmt.Errorf("failed to find matching route")
	}
	return nil
}

func checkLocalIPv6Routes(directPathIPv6NetworkInterface *net.Interface) error {
	if directPathIPv6NetworkInterface == nil {
		return fmt.Errorf("Skipping IPv6 routes check because there is no valid directpath IPv6 network interface on this machine")
	}
	const route = "2001:4860:8040::/42"
	infoLog.Printf("Search for an IPv6 route on network interface: %v matching: %v", directPathIPv6NetworkInterface.Name, route)
	if err := findLocalRoute(*directPathIPv6NetworkInterface, netlink.FAMILY_V6, func(r netlink.Route) bool {
		return strings.Contains(r.Dst.String(), route)
	}); err != nil {
		return fmt.Errorf("Missing route prefix to backends: 2001:4860:8040::/42. IPv6 route setup likely either failed or hasn't been attempted. err: %v", err)
	}
	return nil
}

func checkLocalIPv4Routes(directPathIPv4NetworkInterface *net.Interface, ipv4FromMetadataServer *net.IP, ipv4BalancerIPs []net.IP, balancerPort string) error {
	if directPathIPv4NetworkInterface == nil {
		return fmt.Errorf("Skipping IPv4 routes check because there is not valid DirectPath IPv4 network interface on this machine")
	}
	if len(ipv4BalancerIPs) == 0 {
		return fmt.Errorf("Skipping IPv4 routes check because we didn't find any IPv4 load balancer addresses")
	}
	// First just log the routes on the candidate interface
	if err := findLocalRoute(*directPathIPv4NetworkInterface, netlink.FAMILY_V4, func(r netlink.Route) bool { return true }); err != nil {
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

func getBackendAddrsFromGrpclb(lbAddr string, srvQueriesSucceeded bool) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(alts.NewClientCreds(alts.DefaultClientOptions())),
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
		return nil, fmt.Errorf("Failed to create grpc connection to balancer: %v", err)
	}
	infoLog.Printf("Successfully dialed balancer. Now send initial grpc request...")
	lbClient := lbpb.NewLoadBalancerClient(conn)
	stream, err := lbClient.BalanceLoad(ctx)
	initReq := &lbpb.LoadBalanceRequest{
		LoadBalanceRequestType: &lbpb.LoadBalanceRequest_InitialRequest{
			InitialRequest: &lbpb.InitialLoadBalanceRequest{
				Name: *service,
			},
		},
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to open stream to the balancer: %v", err)
	}
	if err := stream.Send(initReq); err != nil {
		return nil, fmt.Errorf("Failed to send initial grpc request to balancer: %v", err)
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
		return nil, fmt.Errorf("Failed to recv initial grpc response from balancer: %v", err)
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

func resolveBackends(balancerAddress string, srvQueriesSucceeded bool) ([]string, error) {
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
	if backends, err = getBackendAddrsFromGrpclb(balancerAddress, srvQueriesSucceeded); err != nil {
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

func main() {
	flag.Parse()
	infoLog.Println("Running dp_check.")
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
	var balancerHost string
	var balancerPort string
	if len(*balancerTargetOverride) > 0 {
		infoLog.Printf("--balancer_target_override is non-empty. Will override load balancer target used in load balancer connectivity checks and queries to: %v", *balancerTargetOverride)
		var err error
		if balancerHost, balancerPort, err = net.SplitHostPort(*balancerTargetOverride); err != nil {
			infoLog.Printf("ERROR: --balancer_target_override was set to %v, but failed to split into host and port: %v", *balancerTargetOverride, err)
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

	// Check DNS
	srvQueriesSucceeded := false
	runCheck("Service SRV DNS queries", func() error {
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
			balancerHost = srvs[0].Target
			if balancerHost == loadBalancerIPv6OnlyDNS && explicitChecks == 0 {
				skipIPv4Err = fmt.Errorf("%v was detected to be an IPv6-only service because it's DirectPath SRV record pointed to: %v, so DirectPath/IPv4 does not need to work from this VM. Set the flag --ipv4_and_v6 if you want to run this check anyways", *service, loadBalancerIPv6OnlyDNS)
			}
			balancerPort = strconv.Itoa(int(srvs[0].Port))
			infoLog.Println("--balancer_target_override is empty. Will use results from SRV record for the load balancer target used in load balancer connectivity checks and queries")
		}
		infoLog.Printf("Determined load balancer hostname:|%v| and port:|%v|", balancerHost, balancerPort)
		srvQueriesSucceeded = true
		return nil
	})
	if len(balancerHost) == 0 {
		balancerHost = loadBalancerDualstackDNS
		infoLog.Printf("SRV query for _grpclb._tcp.%s failed and --balancer_target_override is unset. Assuming (possible incorrectly) that the load balancer's hostname is %s", *service, balancerHost)
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
		var err error
		infoLog.Printf("Resolve LB IPv6 addrs with:|new(net.Resolver).LookupIP(context.Background(), \"ip6\", \"%v\")|...", balancerHost)
		if ipv6BalancerIPs, err = new(net.Resolver).LookupIP(context.Background(), "ip6", balancerHost); len(ipv6BalancerIPs) == 0 || err != nil {
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
		var err error
		infoLog.Printf("Resolve LB IPv6 addrs with:|new(net.Resolver).LookupIP(context.Background(), \"ip4\", \"%v\")|...", balancerHost)
		ipv4BalancerIPs, err = new(net.Resolver).LookupIP(context.Background(), "ip4", balancerHost)
		// Fail this check if either:
		// a) we expect to resolve LB IPv4 endpoints but don't
		// b) we don't expect to resolve LB IPv4 endpoint but do
		if strings.Compare(balancerHost, loadBalancerDualstackDNS) == 0 {
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
this indicates a possible bug that may be causing a larger outage`, balancerHost, loadBalancerDualstackDNS, *service)
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
		return checkLocalIPv4Routes(directPathIPv4NetworkInterface, ipv4FromMetadataServer, ipv4BalancerIPs, balancerPort)
	})

	// Contact LBs
	tcpOverIPv6ToLoadBalancersSucceeded := false
	runCheck("TCP/IPv6 connectivity to load balancers", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if len(ipv6BalancerIPs) == 0 {
			return fmt.Errorf("Skipping \"TCP/IPv6 connectivity to load balancers\" because prior DNS resolution of LB IPv6 address failed")
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
		if len(ipv4BalancerIPs) == 0 {
			return fmt.Errorf("Skipping \"TCP/IPv4 connectivity to load balancers\" because prior DNS resolution of LB IPv4 address failed")
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
	var ipv6BackendAddrs []string
	runCheck("Discovery of IPv6 backends via load balancers", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if !tcpOverIPv6ToLoadBalancersSucceeded {
			return fmt.Errorf("Skipping discovery of backends via load balancers because TCP connectivity to LBs failed")
		}
		var err error
		ipv6BackendAddrs, err = resolveBackends(net.JoinHostPort(ipv6BalancerIPs[0].String(), balancerPort), srvQueriesSucceeded)
		return err
	})
	var ipv4BackendAddrs []string
	runCheck("Discovery of IPv4 backends via load balancers", func() error {
		if skipIPv4Err != nil {
			return &skipCheckError{err: skipIPv4Err}
		}
		if !tcpOverIPv4ToLoadBalancersSucceeded {
			return fmt.Errorf("Skipping discovery of backends via load balancers because TCP connectivity to LBs failed")
		}
		var err error
		ipv4BackendAddrs, err = resolveBackends(net.JoinHostPort(ipv4BalancerIPs[0].String(), balancerPort), srvQueriesSucceeded)
		return err
	})

	// Contact backends
	tcpConnectivityToIpv6BackendSucceeded := false
	runCheck("TCP connectivity to IPv6 backends", func() error {
		if skipIPv6Err != nil {
			return &skipCheckError{err: skipIPv6Err}
		}
		if len(ipv6BackendAddrs) == 0 {
			return fmt.Errorf("Skipping TCP connectivity to IPv6 backends because discovery of IPv6 backends failed")
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
		if !tcpConnectivityToIpv4BackendSucceeded {
			return fmt.Errorf("skipping secure connectivity to IPv4 backends because TCP connectivity to IPv4 backends did not succeed")
		}
		infoLog.Println("Check secure connectivity to IPv4 backends by attempting to complete all handshakes involved in the setup of a gRPC/ALTS connection to", ipv4BackendAddrs[0])
		return checkSecureConnectivityToBackend(ipv4BackendAddrs[0])
	})
	os.Exit(failureCount)
}
