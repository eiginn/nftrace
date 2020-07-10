package main

import (
	"bufio"
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
	sysctl "github.com/lorenzosaino/go-sysctl"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app         = kingpin.New("nftrace", "Trace packet flow through iptables")
	verbose     = app.Flag("verbose", "Verbose mode.").Short('v').Bool()
	debug       = app.Flag("debug", "Debug mode.").Short('d').Bool()
	timeout     = app.Flag("timeout", "Timeout in seconds").Short('t').Default("30").Int()
	xtablesLock = app.Flag("lock", "Acquire xtables lock for duration of run").Short('l').Bool()
	ipv4        = app.Flag("ipv4", "ipv4 (iptables)").Short('4').Bool()
	ipv6        = app.Flag("ipv6", "ipv6 (ip6tables)").Short('6').Bool()
	traceRule   = app.Arg("rule", "Matching conditions for TRACE rule, omitting assumes handled by user").String()

	ruleset = map[string]map[string][]string{}
)

const (
	lockPath        = "/var/run/xtables.lock"
	nlgroup  uint16 = 0 // 0 MUST be used for TRACE
)

func getTableNames(proto iptables.Protocol) []string {
	var (
		path   string
		tables []string
	)

	if proto == iptables.ProtocolIPv6 {
		path = "/proc/net/ip6_tables_names"
	} else {
		path = "/proc/net/ip_tables_names"
	}

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		tables = append(tables, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return tables
}

func getRuleSet(proto iptables.Protocol) {
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		log.Fatal(err)
	}

	for _, table := range getTableNames(proto) {
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

func insertTraceRule(proto iptables.Protocol, rule *string) {
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		log.Fatal(err)
	}
	chain := strings.Split(*rule, " ")[0]
	matchers := append(strings.Split(*rule, " ")[1:], []string{"-j", "TRACE"}...)
	log.Printf("Adding rule: -t raw -I %s %s", chain, strings.Join(matchers, " "))
	err = ipt.Insert("raw", chain, 1, matchers...)
	if err != nil {
		log.Fatal(err)
	}
}

func cleanTraceRule(proto iptables.Protocol, rule *string) {
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		log.Fatal(err)
	}
	chain := strings.Split(*rule, " ")[0]
	matchers := append(strings.Split(*rule, " ")[1:], []string{"-j", "TRACE"}...)
	log.Printf("Removing rule: -t raw -A %s %s", chain, strings.Join(matchers, " "))
	err = ipt.Delete("raw", chain, matchers...)
	if err != nil {
		log.Printf("WARNING %s\n", err)
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

func checkSysctl(af string) {
	val, err := sysctl.Get(fmt.Sprintf("net.netfilter.nf_log.%s", af))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%#v\n", val)
	if val != "nfnetlink_log" {
		log.Fatalf("nfnetlink_log not loaded for address family, check 'sysctl net.netfilter.nf_log.%s'", af)
	}
}

func main() {
	var ipvProto iptables.Protocol
	app.HelpFlag.Short('h')
	app.Version("0.0.1")
	kingpin.MustParse(app.Parse(os.Args[1:]))
	nflogAF := "2" // ipv4 AF_INET
	if *ipv4 == true && *ipv6 == true {
		app.FatalUsage("Must specify only one of -4 or -6")
	} else if *ipv4 == true {
		ipvProto = iptables.ProtocolIPv4
	} else if *ipv6 == true {
		ipvProto = iptables.ProtocolIPv6
		nflogAF = "10" // ipv6 AF_INET6
	} else {
		ipvProto = iptables.ProtocolIPv4
	}
	checkSysctl(nflogAF)

	// insert TRACE rule
	if *traceRule == "" {
		log.Println("Assuming TRACE rule(s) handled seperately")
	} else {
		insertTraceRule(ipvProto, traceRule)
		// I think this is safe due to LIFO order of defer calls
		// wrt defer fileLock.Unlock() below
		defer cleanTraceRule(ipvProto, traceRule)
	}
	// fetch ruleset before holding lock
	getRuleSet(ipvProto)

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

	// TODO fix sigint not being captured to clean up trace rule
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	fn := func(attrs nflog.Attribute) int {
		// would be nice if we could exclude messages from the wrong address family but
		// attrs does not have it only parent netlink message does
		//fmt.Printf("%#v\n", attrs)
		lookupRule(*attrs.Prefix)
		if *ipv6 == true {
			packet := gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv6, gopacket.Default)
			packet.Dump()
		} else {
			packet := gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv4, gopacket.Default)
			packet.Dump()
		}
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
