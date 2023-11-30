package main

import (
	"fmt"
	"os"
)

func main() {
	//	argsWithoutProg := os.Args[1:]
	//	fmt.Println(argsWithoutProg)

	if len(os.Args) < 2 {
		fmt.Println("Not enough arguments")
		return
	}

	//var fname string = os.Args[1]
	var pcapf PcapFile
	pcapf.Open(os.Args[1])
}
