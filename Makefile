all: build

build:
	go build -mod vendor -v -o nftrace cmd/nftrace/main.go

clean:
	rm -f nftrace
