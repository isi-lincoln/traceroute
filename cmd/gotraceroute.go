package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/isi-lincoln/traceroute"
)

func main() {
	var m = flag.Int("m", traceroute.DEFAULT_MAX_HOPS, `Set the max time-to-live (max number of hops) used in outgoing probe packets (default is 64)`)
	var f = flag.Int("f", traceroute.DEFAULT_FIRST_HOP, `Set the first used time-to-live, e.g. the first hop (default is 1)`)
	var q = flag.Int("q", 1, `Set the number of probes per "ttl" to nqueries (default is one probe).`)
	var src string
	flag.StringVar(&src, "s", "", "Set the source address")

	if len(os.Args) == 1 {
		fmt.Printf("Usage:\n")
		fmt.Printf("%s <destination>\n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()
	host := flag.Arg(0)
	options := traceroute.TracerouteOptions{}
	options.SetRetries(*q - 1)
	options.SetMaxHops(*m + 1)
	options.SetFirstHop(*f)

	ipAddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return
	}

	fmt.Printf("traceroute to %v (%v), %v hops max, %v byte packets\n", host, ipAddr, options.MaxHops(), options.PacketSize())

	c := make(chan traceroute.TracerouteHop, 0)
	go func() {
		for {
			hop, ok := <-c
			if !ok {
				fmt.Println()
				return
			}
			fmt.Println(hop.PrintHop())
		}
	}()

	if src != "" {
		_, err = traceroute.Traceroute(&src, host, &options, c)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	} else {
		_, err = traceroute.Traceroute(nil, host, &options, c)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}
