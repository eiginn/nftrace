package main

import (
	"fmt"

	"github.com/eiginn/nflog-go/nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"os"
	"os/signal"
	"syscall"
)

func real_callback(payload *nflog.Payload) int {
	// TRACE: raw:OUTPUT:rule:3 IN= OUT=vlan100 SRC=198.41.152.201 DST=198.41.253.197 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=21130 DF PROTO=TCP SPT=54988 DPT=80 SEQ=2387601089 ACK=0 WINDOW=65535 RES=0x00 SYN URGP=0 OPT (020405B4010104020103030A) UID=0 GID=0
	fmt.Printf("%s ", payload.GetPrefix())
	fmt.Printf("MARK=%d ", payload.GetNFMark())
	fmt.Printf("IN=%d OUT=%d ", payload.GetInDev(), payload.GetOutDev())
	//fmt.Printf("  Φin %d      Φout %d\n", payload.GetPhysInDev(), payload.GetPhysOutDev())
	//fmt.Println(hex.Dump(payload.Data))
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	//fmt.Printf("  %s\n", pktdump.Format(packet))
	fmt.Println(packet)
	return 0
}

func main() {
	q := new(nflog.Queue)

	q.SetCallback(real_callback)

	q.Init()
	defer q.Close()

	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)

	q.CreateQueue(0)
	q.SetMode(nflog.NFULNL_COPY_PACKET)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.Close()
			os.Exit(0)
			// XXX we should break gracefully from loop
		}
	}()

	// XXX Drop privileges here

	// XXX this should be the loop
	q.TryRun()

	fmt.Printf("hello, world\n")
}
