package main

import (
	"fmt"
	"os"

	"github.com/f18m/go-pcap-analyzer/pkg/pcapfile"
)

func main() {
	//	argsWithoutProg := os.Args[1:]
	//	fmt.Println(argsWithoutProg)

	if len(os.Args) < 2 {
		fmt.Println("Not enough arguments")
		return
	}

	//var fname string = os.Args[1]
	var pcapf pcapfile.PcapFile
	ok, nread := pcapf.Open(os.Args[1])
	if !ok {
		fmt.Printf("Failed to open PCAP file %v\n", os.Args[1])
		return
	}

	defer pcapf.Close()
	fmt.Printf("Successfully opened PCAP file %v and read %v packets\n", os.Args[1], nread)
}
