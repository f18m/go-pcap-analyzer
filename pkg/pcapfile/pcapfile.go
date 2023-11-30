// Package pcapfile contains my own implementation of 100% Golang small library to open .pcap files from disk;
// this is different from the approach of google/gopacket that uses "cgo" utility to wrap the C libpcap API
// in golang, see https://github.com/google/gopacket/blob/master/pcap/pcap_unix.go.
package pcapfile

import (
	"encoding/binary"
	"fmt"
	"os"
)

// PcapHeader describes the binary header of a PCAP file
type PcapHeader struct {
	Magic_number  uint32 /* magic number */
	Version_major uint16 /* major version number */
	Version_minor uint16 /* minor version number */
	Thiszone      uint32 /* GMT to local correction */
	Sigfigs       uint32 /* accuracy of timestamps */
	Snaplen       uint32 /* max length of captured packets in octets */
	Network       uint32 /* data link type */
}

// PcapFile is the main structure exported by this package
type PcapFile struct {
	actual_file *os.File
	hdr         PcapHeader
}

func (pf PcapFile) Open(fname string) bool {
	var err error
	pf.actual_file, err = os.Open(fname)
	if err != nil {
		panic(err) // FIXME do better error handling
		//return false
	}

	err = binary.Read(pf.actual_file, binary.LittleEndian, &pf.hdr)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return false
	}

	//fmt.Printf("%X\n", pf.hdr.Magic_number)
	//fmt.Printf("%+v\n", pf.hdr)
	return true
}

func (pf PcapFile) Close() error {
	fmt.Printf("Closing the PCAP file\n")
	return pf.actual_file.Close()
}
