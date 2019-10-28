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
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	lbpb "google.golang.org/grpc/balancer/grpclb/grpc_lb_v1"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/alts"
)

var (
	service      = flag.String("service", "", "The public DirectPath-enabled DNS of the service to check")
	infoLog      = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	failureCount int
)

const (
	loadBalancerDNS = "grpclb.directpath.google.internal."
)

func cmd(command string) (string, error) {
	c := strings.Split(command, " ")
	out, err := exec.Command(c[0], c[1:]...).Output()
	return string(out), err
}

func getOutput(command string) (string, error) {
	var out string
	var err error
	if out, err = cmd(command); err != nil {
		return "", fmt.Errorf("Command:|%v| FAILED. Error:%v", command, err)
	}
	return string(out), nil
}

func getBackendAddrsFromGrpclb(lbAddr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	conn, err := grpc.DialContext(
		ctx,
		lbAddr,
		grpc.WithTransportCredentials(alts.NewClientCreds(alts.DefaultClientOptions())),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to create grpc connection to balancer: %v", err)
	}
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
		return nil, fmt.Errorf("Failed to send init grpc request to balancer: %v", err)
	}
	reply, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("Failed to recv init grpc response from balancer: %v", err)
	}
	initResp := reply.GetInitialResponse()
	if initResp == nil {
		return nil, fmt.Errorf("gRPC reply from balancer did not include initial response", err)
	}
	if initResp.LoadBalancerDelegate != "" {
		return nil, fmt.Errorf("grpc balancer delegation is not supported")
	}
	// Just wait for the first non-empty server list
	for {
		reply, err = stream.Recv()
		if err != nil {
			return nil, fmt.Errorf("grpc balancer stream Recv error:%v", err)
		}
		if serverList := reply.GetServerList(); serverList != nil {
			var out []string
			for _, s := range serverList.Servers {
				if s.Drop {
					continue
				}
				ip := net.IP(s.IpAddress)
				ipStr := ip.String()
				out = append(out, fmt.Sprintf("[%s]:%v", ipStr, s.Port))
			}
			if len(out) > 0 {
				return out, nil
			}
		}
	}
}

func runCheck(name string, check func() error) {
	if err := check(); err != nil {
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
	if syscall.Getuid() != 0 {
		infoLog.Println("Not running as root, some checks may fail.")
	}
	// Check IPv6
	runCheck("IPv6 routes", func() error {
		var out string
		var err error
		cmd := "ip -6 route show"
		infoLog.Printf("Check IPv6 routes with:|%v|...\n", cmd)
		if out, err = getOutput(cmd); err != nil {
			return err
		}
		if !strings.Contains(out, "2001:4860:8040::/42") {
			return fmt.Errorf(`Missing route prefix to backends: 2001:4860:8040::/42.
IPv6 route setup either failed or hasn't been attempted`)
		}
		return nil
	})
	runCheck("IPv6 addresses", func() error {
		var out string
		var err error
		cmd := "ip -6 addr show"
		infoLog.Printf("Check IPv6 addresses with:|%v|...\n", cmd)
		if out, err = getOutput(cmd); err != nil {
			return err
		}
		if !strings.Contains(out, "inet6 2600") {
			return fmt.Errorf("This VM is missing a global 2600-prefixed IPv6 address. IPv6 DHCP setup either failed or hasn't been attempted")
		}
		return nil
	})

	// Check DNS
	runCheck("Load balancer AAAA DNS queries", func() error {
		var addrs []string
		var err error
		infoLog.Printf("Resolve LB addrs with:|net.LookupHost(\"%v\")|...\n", loadBalancerDNS)
		if addrs, err = net.LookupHost(loadBalancerDNS); len(addrs) == 0 || err != nil {
			return fmt.Errorf(`Load balancer DNS resolution failed: %v.
Either this VM doesn't have DirectPath access, or there is a bug that may be causing a larger outage`, err)
		}
		for _, addr := range addrs {
			infoLog.Printf("Resolved LB addr: %v\n", addr)
		}
		return nil
	})
	var balancerAddr string
	runCheck("Service SRV DNS queries", func() error {
		infoLog.Printf("Lookup service SRV records with:|net.DefaultResolver.LoookupSRV(context.Background(), \"grpclb\", \"tcp\", \"%v\")|...\n", *service)
		_, srvs, err := net.DefaultResolver.LookupSRV(context.Background(), "grpclb", "tcp", *service)
		if err != nil || len(srvs) == 0 {
			return fmt.Errorf(`SRV record resolution for _grpclb._tcp.%s failed with error:|%v|.
The most likely reason for this is that %s is not a DirectPath-enabled service`, *service, err, *service)
		}
		if len(srvs) != 1 {
			return fmt.Errorf("Got %d SRV records:|%v|. This is not necessarily an error but is unexpected", len(srvs), srvs)
		}
		if strings.Compare(srvs[0].Target, loadBalancerDNS) != 0 {
			return fmt.Errorf("Got SRV record target:|%v|; expected:|%v|", srvs[0].Target, loadBalancerDNS)
		}
		balancerAddr = fmt.Sprintf("%v:%v", srvs[0].Target, srvs[0].Port)
		return nil
	})

	// Contact LBs
	tcpToLoadBalancersSucceeded := false
	runCheck("TCP connectivity to load balancers", func() error {
		if len(balancerAddr) == 0 {
			return fmt.Errorf("Skipping TCP connectivity to load balancers because load balancer DNS resolution failed")
		}
		infoLog.Printf("Check TCP connectivity to LB's with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...\n", balancerAddr)
		if _, err := net.DialTimeout("tcp", balancerAddr, time.Second*5); err != nil {
			return fmt.Errorf("TCP connectivity to the load balancer failed: %v. This may be a transient error specific to the load balancer at %v", err, balancerAddr)
		}
		tcpToLoadBalancersSucceeded = true
		return nil
	})
	var backendAddrs []string
	runCheck("Discovery of backends via load balancers", func() error {
		if !tcpToLoadBalancersSucceeded {
			return fmt.Errorf("Skipping discovery of backends via load balancers because TCP connectivity to LBs failed")
		}
		var err error
		infoLog.Printf("Find backend addresses for %v by making a \"BalanceLoad\" RPC to the load balancers...\n", *service)
		if backendAddrs, err = getBackendAddrsFromGrpclb(balancerAddr); err != nil {
			return fmt.Errorf(`Failed to get any backend VIPs from the load balancer because: %v.
Consider running this binary under environment variables:
* GRPC_GO_LOG_VERBOSITY_LEVEL=99
* GRPC_GO_LOG_SEVERITY_LEVEL=INFO
in order to get more debug logs from the grpc library (which was just used when reaching out to the load balancer)`, err)
		}
		for _, addr := range backendAddrs {
			infoLog.Printf("Found backend address:|%v|\n", addr)
		}
		return nil
	})

	// Contact backends
	tcpConnectivitySucceeded := false
	runCheck("TCP connectivity to backends", func() error {
		if len(backendAddrs) == 0 {
			return fmt.Errorf("Skipping TCP connectivity to backends because discovery of backends failed")
		}
		infoLog.Printf("Check TCP connectivity to backends with:|net.DialTimeout(\"tcp\", \"%v\", time.Second*5)|...\n", backendAddrs[0])
		if _, err := net.DialTimeout("tcp", backendAddrs[0], time.Second*5); err != nil {
			return fmt.Errorf("TCP connectivity to backend addr - %v failed: %v", backendAddrs[0], err)
		}
		tcpConnectivitySucceeded = true
		return nil
	})
	runCheck("Secure connectivity to backends", func() error {
		if !tcpConnectivitySucceeded {
			return fmt.Errorf("Skipping secure connectivity to backends because TCP connectivity to backends did not succeed")
		}
		infoLog.Printf("Check secure connectivity to backends by attempting to complete all handshakes involved in the setup of a gRPC/ALTS connection to %v", backendAddrs[0])
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		altsCreds := alts.NewClientCreds(alts.DefaultClientOptions())
		altsCreds.OverrideServerName(*service)
		conn, err := grpc.Dial(backendAddrs[0], grpc.WithTransportCredentials(altsCreds))
		const errMsg = "Secure connectivity to backend addr - %v failed: %v."
		if err != nil {
			return fmt.Errorf(errMsg, backendAddrs[0], err)
		}
		lastState := conn.GetState()
		for lastState != connectivity.Ready {
			select {
			case <-ctx.Done():
				return fmt.Errorf(errMsg, backendAddrs[0], ctx.Err())
			default:
			}
			conn.WaitForStateChange(ctx, lastState)
			lastState = conn.GetState()
		}
		return nil
	})
	os.Exit(failureCount)
}
