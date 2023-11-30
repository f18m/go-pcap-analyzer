.DEFAULT_GOAL := build

fmt:
	go fmt ./...

lint: fmt
	golint ./...

vet: fmt
	go vet ./...

build: vet
	go build -o bin/go-pcap-analyzer cmd/main.go

test: build
	bin/go-pcap-analyzer /storage/pcaps/captured_lab_traffic_sample.pcap

.PHONY: fmt lint vet build test
