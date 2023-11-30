.DEFAULT_GOAL := build

fmt:
	go fmt src/*.go

lint: fmt
	golint src/*.go

vet: fmt
	go vet src/*.go

build: vet
	go build src/main.go
