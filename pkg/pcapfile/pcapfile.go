// Package pcapfile contains my own implementation of 100% Golang small library to open .pcap files from disk;
// this is different from the approach of google/gopacket that uses "cgo" utility to wrap the C libpcap API
// in golang, see https://github.com/google/gopacket/blob/master/pcap/pcap_unix.go.
package pcapfile

import (
	"bufio"
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

	// create the buffered Reader
	buffReader := bufio.NewReader(pf.ActualFile)

	// read the header
	err = binary.Read(buffReader, binary.LittleEndian, &pf.Hdr)
	if err != nil {
		fmt.Println("Failed to read the PCAP header:", err)
		return false, nreadPkts
	}

	//fmt.Printf("%X\n", pf.Hdr.Magic_number)
	//fmt.Printf("%+v\n", pf.Hdr)

	// now loop till there is a packet
	var nResizeOps uint
	var pktPayload []byte //= make([]byte, pktHdr.InclLen)
	for {

		// read packet header
		var pktHdr PcaprecHdr
		err = binary.Read(buffReader, binary.LittleEndian, &pktHdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Failed to read a packet:", err)
			return false, nreadPkts
		}

		//fmt.Printf("%+v\n", pktHdr)

		// prepare buffer
		if int(pktHdr.InclLen) > cap(pktPayload) {
			// garbage-collect the old buffer and create a larger, new buffer
			pktPayload = make([]byte, pktHdr.InclLen)
			nResizeOps++
		} else {
			// keep using current buffer, but resize it:
			pktPayload = pktPayload[:pktHdr.InclLen]
		}

		// read the packet payload

		nreadBytes, err := buffReader.Read(pktPayload)
		if err != nil {
			fmt.Println("Failed to read a packet:", err)
			return false, nreadPkts
		}
		if nreadBytes != int(pktHdr.InclLen) {
			// try again since bufio.Read() launches at most 1 io.Read() on the underlying file object
			// so it's possible we cannot read the whole packet in 1 single call
			var pktPayloadMissing []byte = make([]byte, pktHdr.InclLen-uint32(nreadBytes))
			nreadBytes2, err := buffReader.Read(pktPayloadMissing)
			if err != nil {
				fmt.Println("Failed to read a packet:", err)
				return false, nreadPkts
			}

			var totReadBytes = nreadBytes + nreadBytes2
			if totReadBytes != int(pktHdr.InclLen) {
				fmt.Println("Failed to read packet #", nreadPkts, ": read only", totReadBytes, "bytes out of expected", pktHdr.InclLen)
				return false, nreadPkts
			}
		}

		//fmt.Println("Read ", nreadBytes, " bytes")
		nreadPkts++
	}

	fmt.Println("Done ", nResizeOps, " buffer resizing ops; max packet len was", cap(pktPayload), "bytes")

	return true, nreadPkts
}

func (pf PcapFile) Close() error {
	fmt.Printf("Closing the PCAP file\n")
	return pf.ActualFile.Close()
}
