VERSION := $(shell git describe --tags --always --dirty=-dev)

.PHONY: all build clean test
all: build

build:
	go build -mod vendor -v -o nftrace -ldflags="-X 'github.com/eiginn/nftrace.BuildVersion=$(VERSION)'" cmd/nftrace/main.go

clean:
	rm -f nftrace
