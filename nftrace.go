package nftrace

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/eiginn/nftrace/pktdump"
	"github.com/florianl/go-nflog/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	sysctl "github.com/lorenzosaino/go-sysctl"
)

var (
	ruleset = map[string]map[string][]string{}
	packets = packetagg{ids: make(map[string]gopacket.Packet)}
	ipv6    = false
)

const (
	lockPath        = "/var/run/xtables.lock"
	nlgroup  uint16 = 0 // 0 MUST be used for TRACE
)

type packetagg = struct {
	sync.RWMutex
	ids map[string]gopacket.Packet
}

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

func SetIPv6(b bool) {
	if b == true {
		ipv6 = true
	}
}

func GetRuleSet(proto iptables.Protocol) {
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

func InsertTraceRule(proto iptables.Protocol, chain string, rule *string, limit *string) {
	var matchers []string
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		log.Fatal(err)
	}
	if *limit != "" {
		matchers = append(strings.Split(*rule, " "), []string{"-m", "limit", "--limit", *limit, "-j", "TRACE"}...)
	} else {
		matchers = append(strings.Split(*rule, " "), []string{"-j", "TRACE"}...)
	}
	log.Printf("Adding rule: -t raw -I %s %s", chain, strings.Join(matchers, " "))
	err = ipt.Insert("raw", chain, 1, matchers...)
	if err != nil {
		log.Fatal(err)
	}
}

func CleanTraceRule(proto iptables.Protocol, chain string, rule *string, limit *string) {
	var matchers []string
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		log.Fatal(err)
	}
	if *limit != "" {
		matchers = append(strings.Split(*rule, " "), []string{"-m", "limit", "--limit", *limit, "-j", "TRACE"}...)
	} else {
		matchers = append(strings.Split(*rule, " "), []string{"-j", "TRACE"}...)
	}
	err = ipt.Delete("raw", chain, matchers...)
	if err != nil {
		log.Printf("WARNING %s\n", err)
	} else {
		log.Printf("Removing rule: -t raw -A %s %s", chain, strings.Join(matchers, " "))
	}
}

func lookupRule(packet gopacket.Packet, prefix string) string {
	fields := strings.Split(strings.TrimPrefix(string(prefix), "TRACE: "), ":")
	rulenum, err := strconv.Atoi(strings.TrimSpace(fields[3]))
	if err != nil {
		log.Fatal(err)
	}
	id := packetID(packet.Data())
	switch kind := fields[2]; kind {
	case "policy":
		return fmt.Sprintf("%s %s %#v", id[:12], prefix, ruleset[fields[0]][fields[1]][0])
	case "rule":
		return fmt.Sprintf("%s %s %#v", id[:12], prefix, ruleset[fields[0]][fields[1]][rulenum])
	}

	return fmt.Sprintf("%s %s", id[:12], prefix)
}

func addPacketAgg(packet gopacket.Packet) {
	id := packetID(packet.Data())
	packets.RLock()
	if _, ok := packets.ids[id]; ok == false {
		packets.RUnlock()
		packets.Lock()
		if _, ok := packets.ids[id]; ok == false {
			packets.ids[id] = packet
		}
		packets.Unlock()
	} else {
		packets.RUnlock()
	}
}

func packetID(rawpacket []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(rawpacket))
}

func CheckSysctl(af string) {
	val, err := sysctl.Get(fmt.Sprintf("net.netfilter.nf_log.%s", af))
	if err != nil {
		log.Fatal(err)
	}
	if val != "nfnetlink_log" {
		log.Fatalf("nfnetlink_log not loaded for address family, 'modprobe nfnetlink_log' kernel module and "+
			"enable it with: 'sysctl -w net.netfilter.nf_log.%s=nfnetlink_log'", af)
	}
}

func CheckNftCompat() {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		log.Println("Warning: Could not check loaded kernel modules")
		return
	}

	if strings.Contains(string(data), "nft_compat") {
		log.Fatalf("ERROR: nft_compat kernel module is loaded. This tool only works with iptables-legacy, " +
			"not with nftables compatibility layer. See manpage of xtables-nft and use xtables-monitor.")
	}
}

func PrintPackets(verbose bool) {
	packets.RLock()
	if verbose == true {
		for id, p := range packets.ids {
			fmt.Printf("%s %s\n", id[:12], p)
		}
	} else {
		for id, p := range packets.ids {
			fmt.Printf("%s %s\n", id[:12], pktdump.Format(p))
		}
	}
	packets.RUnlock()
	fmt.Println("")
}

func PrintTrace(attrs nflog.Attribute) int {
	// would be nice if we could exclude messages from the wrong address family but
	// attrs does not have it only parent netlink message does
	//fmt.Printf("%#v\n", attrs)

	// We could get non netfilter trace messages on group 0
	// like nf_conntrack_log_invalid
	if !strings.Contains(*attrs.Prefix, "TRACE:") {
		return 0
	}
	if ipv6 == true {
		packet := gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv6, gopacket.Default)
		fmt.Printf("%s\n", lookupRule(packet, *attrs.Prefix))
		addPacketAgg(packet)
	} else {
		packet := gopacket.NewPacket(*attrs.Payload, layers.LayerTypeIPv4, gopacket.Default)
		fmt.Printf("%s\n", lookupRule(packet, *attrs.Prefix))
		addPacketAgg(packet)
	}
	return 0
}
