/*
 PcapFile implementation
*/

package pcapfile

import (
	"encoding/binary"
	"fmt"
	"os"
)

type PcapHeader struct {
	magic_number  uint32 /* magic number */
	version_major uint16 /* major version number */
	version_minor uint16 /* minor version number */
	thiszone      uint32 /* GMT to local correction */
	sigfigs       uint32 /* accuracy of timestamps */
	snaplen       uint32 /* max length of captured packets in octets */
	network       uint32 /* data link type */
}

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

	var hdr PcapHeader
	err = binary.Read(pf.actual_file, binary.LittleEndian, &hdr.magic_number)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return false
	}

	return true
}
