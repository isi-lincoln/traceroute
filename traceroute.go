// Package traceroute provides functions for executing a tracroute to a remote
// host.
package traceroute

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const DEFAULT_PORT = 33434
const DEFAULT_MAX_HOPS = 32
const DEFAULT_FIRST_HOP = 1
const DEFAULT_TIMEOUT_MS = 500
const DEFAULT_RETRIES = 3
const DEFAULT_PACKET_SIZE = 52

// Return the first non-loopback address. This address is used for sending packets out.
func GetFirstSocketAddress() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				return ipnet.IP, nil
			}
		}
	}

	return nil, errors.New("You do not appear to be connected to the Internet")
}

// Given a host name convert it to a 4 byte IP address.
func destAddr(dest string) (net.IP, error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return nil, err
	}
	addr := addrs[0]

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return nil, err
	}

	return ipAddr.IP, nil
}

// TracrouteOptions type
type TracerouteOptions struct {
	port       int
	maxHops    int
	firstHop   int
	timeoutMs  int
	retries    int
	packetSize int
}

func (options *TracerouteOptions) Port() int {
	if options.port == 0 {
		options.port = DEFAULT_PORT
	}
	return options.port
}

func (options *TracerouteOptions) SetPort(port int) {
	options.port = port
}

func (options *TracerouteOptions) MaxHops() int {
	if options.maxHops == 0 {
		options.maxHops = DEFAULT_MAX_HOPS
	}
	return options.maxHops
}

func (options *TracerouteOptions) SetMaxHops(maxHops int) {
	options.maxHops = maxHops
}

func (options *TracerouteOptions) FirstHop() int {
	if options.firstHop == 0 {
		options.firstHop = DEFAULT_FIRST_HOP
	}
	return options.firstHop
}

func (options *TracerouteOptions) SetFirstHop(firstHop int) {
	options.firstHop = firstHop
}

func (options *TracerouteOptions) TimeoutMs() int {
	if options.timeoutMs == 0 {
		options.timeoutMs = DEFAULT_TIMEOUT_MS
	}
	return options.timeoutMs
}

func (options *TracerouteOptions) SetTimeoutMs(timeoutMs int) {
	options.timeoutMs = timeoutMs
}

func (options *TracerouteOptions) Retries() int {
	if options.retries == 0 {
		options.retries = DEFAULT_RETRIES
	}
	return options.retries
}

func (options *TracerouteOptions) SetRetries(retries int) {
	options.retries = retries
}

func (options *TracerouteOptions) PacketSize() int {
	if options.packetSize == 0 {
		options.packetSize = DEFAULT_PACKET_SIZE
	}
	return options.packetSize
}

func (options *TracerouteOptions) SetPacketSize(packetSize int) {
	options.packetSize = packetSize
}

// TracerouteHop type
type TracerouteHop struct {
	Success     bool
	Address     net.IP
	Host        string
	N           int
	ElapsedTime time.Duration
	TTL         int
}

func (hop *TracerouteHop) PrintHop() string {
	addr := hop.Address.String()
	hostOrAddr := addr
	if hop.Host != "" {
		hostOrAddr = hop.Host
	}
	output := ""
	if hop.Success {
		output = fmt.Sprintf("%-3d %v %v (%v) %v\n", hop.TTL, addr, hostOrAddr, hop.ElapsedTime)
	} else {
		output = fmt.Sprintf("%-3d *\n", hop.TTL)
	}

	return output
}

func (hop *TracerouteHop) AddressString() string {
	return hop.Address.String()
}

func (hop *TracerouteHop) HostOrAddressString() string {
	if hop.Host != "" {
		return hop.Host
	}
	return hop.Address.String()
}

// TracerouteResult type
type TracerouteResult struct {
	DestinationAddress net.IP
	Hops               []TracerouteHop
}

func notify(hop TracerouteHop, channels []chan TracerouteHop) {
	for _, c := range channels {
		c <- hop
	}
}

func closeNotify(channels []chan TracerouteHop) {
	for _, c := range channels {
		close(c)
	}
}

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

// Traceroute uses the given dest (hostname) and options to execute a traceroute
// from your machine to the remote host.
//
// Outbound packets are UDP packets and inbound packets are ICMP.
//
// Returns a TracerouteResult which contains an array of hops. Each hop includes
// the elapsed time and its IP address.
func Traceroute(source *string, dest string, options *TracerouteOptions, c ...chan TracerouteHop) (*TracerouteResult, error) {
	result := &TracerouteResult{
		Hops: []TracerouteHop{},
	}

	destAddr, err := destAddr(dest)
	result.DestinationAddress = destAddr

	var socketAddr net.IP
	if source == nil {
		socketAddr, err = GetFirstSocketAddress()
		if err != nil {
			return nil, err
		}
	} else {
		ipAddr := net.ParseIP(*source)
		if ipAddr == nil {
			return nil, fmt.Errorf("source was not a valid ip address: %s", *source)
		}

		socketAddr = ipAddr
	}

	fmt.Printf("Traceroute Debug: selected source address: %s", socketAddr)

	timeoutMs := (int64)(options.TimeoutMs())
	tv := syscall.NsecToTimeval(1000 * 1000 * timeoutMs)

	ttl := options.FirstHop()
	retry := 0
	for {
		//log.Println("TTL: ", ttl)
		start := time.Now()

		if isIPv4(socketAddr) {
			// Set up the socket to receive inbound packets
			recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
			if err != nil {
				return result, err
			}

			// Set up the socket to send packets out.
			sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
			if err != nil {
				return result, err
			}
			// This sets the current hop TTL
			syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
			// This sets the timeout to wait for a response from the remote host
			syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

			defer syscall.Close(recvSocket)
			defer syscall.Close(sendSocket)

			// Bind to the local socket to listen for ICMP packets
			var srcAddr4 [4]byte
			if ip4 := socketAddr.To4(); ip4 != nil {
				copy(srcAddr4[:], ip4)
			}
			syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: options.Port(), Addr: srcAddr4})

			var dstAddr4 [4]byte
			if ip4 := destAddr.To4(); ip4 != nil {
				copy(dstAddr4[:], ip4)
			}
			// Send a single null byte UDP packet
			syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: options.Port(), Addr: dstAddr4})

			var p = make([]byte, options.PacketSize())
			n, from, err := syscall.Recvfrom(recvSocket, p, 0)
			elapsed := time.Since(start)
			if err == nil {
				cAddr := from.(*syscall.SockaddrInet4).Addr
				currAddr := net.IPv4(cAddr[0], cAddr[1], cAddr[2], cAddr[3])

				hop := TracerouteHop{Success: true, Address: currAddr, N: n, ElapsedTime: elapsed, TTL: ttl}

				// TODO: this reverse lookup appears to have some standard timeout that is relatively
				// high. Consider switching to something where there is greater control.
				currHost, err := net.LookupAddr(hop.AddressString())
				if err == nil {
					hop.Host = currHost[0]
				}

				notify(hop, c)

				result.Hops = append(result.Hops, hop)

				ttl += 1
				retry = 0

				dAddr := net.IPv4(dstAddr4[0], dstAddr4[1], dstAddr4[2], dstAddr4[3])
				if ttl > options.MaxHops() || currAddr.Equal(dAddr) {
					closeNotify(c)
					return result, nil
				}
			} else {
				retry += 1
				if retry > options.Retries() {
					notify(TracerouteHop{Success: false, TTL: ttl}, c)
					ttl += 1
					retry = 0
				}

				if ttl > options.MaxHops() {
					closeNotify(c)
					return result, nil
				}
			}
		} else {
			// Set up the socket to receive inbound packets
			recvSocket, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
			if err != nil {
				return result, err
			}

			// Set up the socket to send packets out.
			sendSocket, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
			if err != nil {
				return result, err
			}
			// This sets the current hop TTL
			syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
			// This sets the timeout to wait for a response from the remote host
			syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

			defer syscall.Close(recvSocket)
			defer syscall.Close(sendSocket)

			// Bind to the local socket to listen for ICMP packets
			var srcAddr6 [16]byte
			if ip6 := socketAddr.To16(); ip6 != nil {
				copy(srcAddr6[:], ip6)
			}
			syscall.Bind(recvSocket, &syscall.SockaddrInet6{Port: options.Port(), Addr: srcAddr6})

			var dstAddr6 [16]byte
			if ip6 := destAddr.To16(); ip6 != nil {
				copy(dstAddr6[:], ip6)
			}

			// Send a single null byte UDP packet
			syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet6{Port: options.Port(), Addr: dstAddr6})

			var p = make([]byte, options.PacketSize())
			n, from, err := syscall.Recvfrom(recvSocket, p, 0)
			elapsed := time.Since(start)
			if err == nil {
				cAddr := from.(*syscall.SockaddrInet6).Addr
				currAddr := net.IP(cAddr[:])

				hop := TracerouteHop{Success: true, Address: currAddr, N: n, ElapsedTime: elapsed, TTL: ttl}

				// TODO: this reverse lookup appears to have some standard timeout that is relatively
				// high. Consider switching to something where there is greater control.
				currHost, err := net.LookupAddr(hop.AddressString())
				if err == nil {
					hop.Host = currHost[0]
				}

				notify(hop, c)

				result.Hops = append(result.Hops, hop)

				ttl += 1
				retry = 0

				dAddr := net.IP(destAddr[:])
				if ttl > options.MaxHops() || currAddr.Equal(dAddr) {
					closeNotify(c)
					return result, nil
				}
			} else {
				retry += 1
				if retry > options.Retries() {
					notify(TracerouteHop{Success: false, TTL: ttl}, c)
					ttl += 1
					retry = 0
				}

				if ttl > options.MaxHops() {
					closeNotify(c)
					return result, nil
				}
			}
		}

	}
}
