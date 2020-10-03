package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/eiginn/nftrace"
	"github.com/florianl/go-nflog/v2"
	"github.com/gofrs/flock"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app         = kingpin.New("nftrace", "Trace packet flow through iptables")
	verbose     = app.Flag("verbose", "Verbose mode.").Short('v').Bool()
	debug       = app.Flag("debug", "Debug mode.").Short('d').Bool()
	timeout     = app.Flag("timeout", "Timeout in seconds").Short('t').Default("30").Int()
	ruleLimit   = app.Flag("limit", "--limit value injected into rules, like '2/min'").Short('l').String()
	xtablesLock = app.Flag("lock", "Acquire xtables lock for duration of run").Short('L').Bool()
	ipv4        = app.Flag("ipv4", "ipv4 (iptables)").Short('4').Bool()
	ipv6        = app.Flag("ipv6", "ipv6 (ip6tables)").Short('6').Bool()
	preRule     = app.Flag("prerouting", "rule for raw table PREROUTING").Short('p').PlaceHolder("RULE").String()
	outRule     = app.Flag("output", "rule for raw table OUTPUT").Short('o').PlaceHolder("RULE").String()
)

const (
	lockPath        = "/var/run/xtables.lock"
	nlgroup  uint16 = 0 // 0 MUST be used for TRACE
)

func main() {
	var ipvProto iptables.Protocol
	app.HelpFlag.Short('h')
	app.Version(nftrace.BuildVersion)

	kingpin.MustParse(app.Parse(os.Args[1:]))
	nflogAF := "2" // ipv4 AF_INET
	if *ipv4 == true && *ipv6 == true {
		app.FatalUsage("Must specify only one of -4 or -6")
	} else if *ipv4 == true {
		ipvProto = iptables.ProtocolIPv4
	} else if *ipv6 == true {
		ipvProto = iptables.ProtocolIPv6
		nflogAF = "10" // ipv6 AF_INET6
		nftrace.SetIPv6(true)
	} else {
		ipvProto = iptables.ProtocolIPv4
	}
	nftrace.CheckSysctl(nflogAF)

	// insert TRACE rule(s)
	if *preRule == "" && *outRule == "" {
		log.Println("Assuming TRACE rule(s) handled seperately")
	} else {
		if *preRule != "" {
			nftrace.InsertTraceRule(ipvProto, "PREROUTING", preRule, ruleLimit)
			// I think this is safe due to LIFO order of defer calls
			// wrt defer fileLock.Unlock() below
			defer nftrace.CleanTraceRule(ipvProto, "PREROUTING", preRule, ruleLimit)
		}
		if *outRule != "" {
			nftrace.InsertTraceRule(ipvProto, "OUTPUT", outRule, ruleLimit)
			// I think this is safe due to LIFO order of defer calls
			// wrt defer fileLock.Unlock() below
			defer nftrace.CleanTraceRule(ipvProto, "OUTPUT", outRule, ruleLimit)
		}
	}
	// fetch ruleset before holding lock
	nftrace.GetRuleSet(ipvProto)

	// hold xtables lock
	if *xtablesLock == true {
		fileLock := flock.New(lockPath)
		log.Printf("Trying to acquire the lock: %s\n", fileLock.Path())
		locked, err := fileLock.TryLock()
		if err != nil {
			log.Fatalf("Error acquiring xtables lock: %s\n", fileLock.Path())
		}
		if locked == false {
			log.Fatalf("Could not acquire xtables lock: %s\n", fileLock.Path())
		}
		defer fileLock.Unlock()
	}
	// open socket and start processing messages
	config := nflog.Config{
		Group:       nlgroup,
		Copymode:    nflog.CopyPacket,
		ReadTimeout: 10 * time.Millisecond,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		log.Fatalln("could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	// signal handling context for ctrl-c (SIGINT)
	sigctx, sigcancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	defer func() {
		signal.Stop(signalChan)
		sigcancel()
	}()
	go func() {
		select {
		case <-signalChan: // first signal, cancel context
			sigcancel()
		case <-sigctx.Done():
		}
		<-signalChan // second signal, hard exit
		os.Exit(2)
	}()

	// timeout handling context uses previous context
	ctx, cancel := context.WithTimeout(sigctx, time.Duration(*timeout)*time.Second)
	defer cancel()

	err = nf.Register(ctx, nftrace.PrintTrace)
	if err != nil {
		log.Fatalln(err)
		return
	}

	<-ctx.Done()

	fmt.Printf("\nAggregated packets:\n")
	nftrace.PrintPackets(*verbose)
}
