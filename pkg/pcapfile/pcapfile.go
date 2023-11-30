// Package pcapfile contains my own implementation of 100% Golang small library to open .pcap files from disk;
// this is different from the approach of google/gopacket that uses "cgo" utility to wrap the C libpcap API
// in golang, see https://github.com/google/gopacket/blob/master/pcap/pcap_unix.go.
package pcapfile

import (
	"encoding/binary"
	"fmt"
	"io"
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

// PcaprecHdr describes the binary header of each packet inside a PCAP file
type PcaprecHdr struct {
	TsSec   uint32 /* timestamp seconds */
	TsUsec  uint32 /* timestamp microseconds */
	InclLen uint32 /* number of octets of packet saved in file */
	OrigLen uint32 /* actual length of packet */
}

// PcapFile is the main structure exported by this package
type PcapFile struct {
	ActualFile *os.File
	Hdr        PcapHeader
}

func (pf PcapFile) Open(fname string) (bool, uint) {
	var nreadPkts uint
	var err error
	pf.ActualFile, err = os.Open(fname)
	if err != nil {
		panic(err) // FIXME do better error handling
		//return false
	}

	// read the header
	err = binary.Read(pf.ActualFile, binary.LittleEndian, &pf.Hdr)
	if err != nil {
		fmt.Println("Failed to read the PCAP header:", err)
		return false, nreadPkts
	}

	//fmt.Printf("%X\n", pf.Hdr.Magic_number)
	//fmt.Printf("%+v\n", pf.Hdr)

	// now loop till there is a packet
	for {

		// read packet header
		var pktHdr PcaprecHdr
		err = binary.Read(pf.ActualFile, binary.LittleEndian, &pktHdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Failed to read a packet:", err)
			return false, nreadPkts
		}

		//fmt.Printf("%+v\n", pktHdr)

		// read the packet payload
		var pktPayload []byte = make([]byte, pktHdr.InclLen)
		//err = binary.Read(pf.ActualFile, binary.LittleEndian, &pktPayload)
		_, err := pf.ActualFile.Read(pktPayload)
		if err != nil {
			fmt.Println("Failed to read a packet:", err)
			return false, nreadPkts
		}

		//fmt.Println("Read ", nread, " bytes")
		nreadPkts++
	}

	return true, nreadPkts
}

func (pf PcapFile) Close() error {
	fmt.Printf("Closing the PCAP file\n")
	return pf.ActualFile.Close()
}
