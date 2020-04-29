package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nflog"
	"github.com/gofrs/flock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopkg.in/alecthomas/kingpin.v2"
)

const lockPath = "/run/xtables.lock"

var (
	app         = kingpin.New("nftrace", "Trace packet flow through iptables")
	verbose     = app.Flag("verbose", "Verbose mode.").Short('v').Bool()
	debug       = app.Flag("debug", "Debug mode.").Short('d').Bool()
	timeout     = app.Flag("timeout", "Timeout in seconds").Short('t').Default("30").Int()
	nlgroup     = app.Flag("group", "nfnetlink group, 0 *MUST* be used for TRACE").Short('g').Default("0").Uint16()
	xtablesLock = app.Flag("lock", "Acquire xtables lock for duration of run").Short('l').Bool()
	traceRule   = app.Arg("rule", "Matching conditions for TRACE rule, omitting assumes handled by user").String()

	ruleset = map[string]map[string][]string{}
)

func getRuleSet(proto iptables.Protocol) {
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		log.Fatal(err)
	}

	for _, table := range []string{"nat", "mangle", "raw", "security", "filter"} {
		ruleset[table] = map[string][]string{}
		chains, _ := ipt.ListChains(table)
		for _, chain := range chains {
			ruleset[table][chain] = []string{}
			rules, _ := ipt.List(table, chain)
			for _, rule := range rules {
				ruleset[table][chain] = append(ruleset[table][chain], rule)
			}
		}
	}
}

func lookupRule(prefix string) string {
	fields := strings.Split(strings.TrimPrefix(string(prefix), "TRACE: "), ":")
	rulenum, err := strconv.Atoi(strings.TrimSpace(fields[3]))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s ", prefix)
	switch kind := fields[2]; kind {
	case "policy":
		fmt.Printf("%#v", ruleset[fields[0]][fields[1]][0])
	//case "return":
	//	fmt.Println(prefix)
	//	fmt.Printf("%#v\n", fields)
	case "rule":
		fmt.Printf("%#v", ruleset[fields[0]][fields[1]][rulenum])
	}
	fmt.Println("")

	return prefix
}

func main() {
	app.HelpFlag.Short('h')
	app.Version("0.0.1")
	kingpin.MustParse(app.Parse(os.Args[1:]))
	getRuleSet(iptables.ProtocolIPv4)

	// insert TRACE rule

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
		Group:       *nlgroup,
		Copymode:    nflog.CopyPacket,
		ReadTimeout: 10 * time.Millisecond,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		log.Fatalln("could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	fn := func(attrs nflog.Attribute) int {
		lookupRule(*attrs.Prefix)
		packet := gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv4, gopacket.Default)
		packet.Dump()
		return 0
	}

	err = nf.Register(ctx, fn)
	if err != nil {
		log.Fatalln(err)
		return
	}

	<-ctx.Done()

	// handle rule cleanup
}
