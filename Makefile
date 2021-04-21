VERSION := $(shell git describe --tags --always --dirty=-dev)
export VERSION

.PHONY: all build clean test
all: build

build:
	mkdir -p dist
	go build -mod vendor -v -o dist/nftrace -ldflags="-X 'github.com/eiginn/nftrace.BuildVersion=$(VERSION)'" cmd/nftrace/main.go

clean:
	rm -rf dist
