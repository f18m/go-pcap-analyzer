SHELL = /bin/bash
PCAP_FN:=/storage/pcaps/captured_lab_traffic_sample.pcap
.DEFAULT_GOAL := build

fmt:
	go fmt ./...

lint: fmt
	golint ./...

vet: fmt
	go vet ./...

build: vet
	go build -o bin/go-pcap-analyzer cmd/main.go

benchmark-lpa:
	time large_pcap_analyzer -p $(PCAP_FN)

benchmark-go: build
	time bin/go-pcap-analyzer $(PCAP_FN)

benchmarks:
	$(MAKE) -s benchmark-lpa
	$(MAKE) -s benchmark-go

.PHONY: fmt lint vet build test
