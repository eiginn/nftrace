package pktdump

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestPacketICMPv6(t *testing.T) {
	reqPkt := gopacket.NewPacket([]byte{0x60, 0x02, 0x5b, 0xd9, 0x00, 0x10, 0x3a, 0xff, 0x2a, 0x01, 0x02, 0xa8, 0x85, 0x02, 0x1f, 0x01, 0x45, 0x38, 0x31, 0x33, 0x04, 0x0f, 0x0a, 0x2a, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x4a, 0x26, 0xb2, 0x81, 0x00, 0x00, 0x5b, 0xe8, 0x90, 0x95, 0x00, 0x02, 0x1b, 0x3c}, layers.LayerTypeIPv6, gopacket.Default)
	repPkt := gopacket.NewPacket([]byte{0x64, 0x80, 0x00, 0x00, 0x00, 0x10, 0x3a, 0x2b, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x01, 0x02, 0xa8, 0x85, 0x02, 0x1f, 0x01, 0x45, 0x38, 0x31, 0x33, 0x04, 0x0f, 0x0a, 0x2a, 0x81, 0x00, 0x49, 0x26, 0xb2, 0x81, 0x00, 0x00, 0x5b, 0xe8, 0x90, 0x95, 0x00, 0x02, 0x1b, 0x3c}, layers.LayerTypeIPv6, gopacket.Default)
	tables := []struct {
		packet   *gopacket.Packet
		icmp     *layers.ICMPv6
		src      string
		dst      string
		length   int
		expected string
	}{
		{nil, &layers.ICMPv6{}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP6, length 1234"},
		{&reqPkt, &layers.ICMPv6{TypeCode: layers.ICMPv6TypeEchoRequest << 8}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP6, echo request, id 45697, seq 0, length 1234"},
		{&repPkt, &layers.ICMPv6{TypeCode: layers.ICMPv6TypeEchoReply << 8}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP6, echo reply, id 45697, seq 0, length 1234"},
	}

	for _, table := range tables {
		got := formatPacketICMPv6(table.packet, table.icmp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketICMPv6 was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestPacketICMPv4(t *testing.T) {
	tables := []struct {
		icmp     *layers.ICMPv4
		src      string
		dst      string
		length   int
		expected string
	}{
		{&layers.ICMPv4{}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo reply, id 0, seq 0, length 1234"},
		{&layers.ICMPv4{Id: 999, Seq: 10}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo reply, id 999, seq 10, length 1234"},
		{&layers.ICMPv4{TypeCode: 0x0800}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo request, id 0, seq 0, length 1234"},
		{&layers.ICMPv4{TypeCode: 0xff00}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP, length 1234"},
	}

	for _, table := range tables {
		got := formatPacketICMPv4(table.icmp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketICMPv4 was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestPacketTCP(t *testing.T) {
	tables := []struct {
		tcp      *layers.TCP
		src      string
		dst      string
		length   int
		expected string
	}{
		{&layers.TCP{}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 0:1234, win 0, length 1234"},
		{&layers.TCP{Seq: 999, Window: 95}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 999:2233, win 95, length 1234"},
		{&layers.TCP{DataOffset: 4}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 0:1218, win 0, length 1218"},
		{&layers.TCP{SYN: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S], seq 0:1234, win 0, length 1234"},
		{&layers.TCP{SYN: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{PSH: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [P.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{FIN: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [F], seq 0:1234, win 0, length 1234"},
		{&layers.TCP{FIN: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [F.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{FIN: true, SYN: true, RST: true, PSH: true, ACK: true, URG: true, ECE: true, CWR: true, NS: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [FSRP.UEWN], seq 0:1234, ack 0, win 0, urg 0, length 1234"},
		{&layers.TCP{SYN: true, Options: []layers.TCPOption{{OptionType: 123, OptionLength: 4, OptionData: []byte{0x12, 0x34}}}}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S], seq 0:1234, win 0, options [unknown-123 0x1234], length 1234"},
	}

	for _, table := range tables {
		got := formatPacketTCP(table.tcp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketTCP was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestPacketUDP(t *testing.T) {
	pkt := gopacket.NewPacket([]byte{0x45, 0x00, 0x00, 0x42, 0x9a, 0x66, 0x00, 0x00, 0x40, 0x11, 0xce, 0xc0, 0xc0, 0xa8, 0x48, 0x32, 0xc0, 0xa8, 0x48, 0x01, 0xfb, 0x6a, 0x00, 0x35, 0x00, 0x2e, 0x02, 0xeb, 0x29, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x73, 0x69, 0x67, 0x69, 0x6e, 0x74, 0x02, 0x63, 0x68, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, layers.LayerTypeIPv4, gopacket.Default)
	tables := []struct {
		packet   *gopacket.Packet
		udp      *layers.UDP
		src      string
		dst      string
		expected string
	}{
		{nil, &layers.UDP{Length: 1234}, "test-src", "test-dst", "test-src.0 > test-dst.0: UDP, length 1226"},
		{nil, &layers.UDP{Length: 1234, SrcPort: 68, DstPort: 67}, "test-src", "test-dst", "test-src.68 > test-dst.67: UDP, length 1226"},
		{&pkt, &layers.UDP{Length: 46, SrcPort: 61187, DstPort: 53}, "test-src", "test-dst", "test-src.61187 > test-dst.53: 10628+ [1au] A CH? sigint.ch. (38)"},
	}

	for _, table := range tables {
		got := formatPacketUDP(table.packet, table.udp, table.src, table.dst)
		if got != table.expected {
			t.Errorf("formatPacketUDP was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestPacketDNS(t *testing.T) {
	tables := []struct {
		dns      *layers.DNS
		src      string
		dst      string
		srcPort  int
		dstPort  int
		length   int
		expected string
	}{
		{&layers.DNS{}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 [0q] (1234)"},
		{&layers.DNS{QDCount: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 (1234)"},
		{&layers.DNS{ID: 999, RD: true, ANCount: 2, NSCount: 10, ARCount: 5, Z: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+% [2a] [0q] [10n] [5au] (1234)"},
		{&layers.DNS{ID: 999, RD: true, QDCount: 1, ANCount: 2, NSCount: 10, ARCount: 5, Z: 2}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [2a] [10n] [5au] (1234)"},
		{&layers.DNS{ID: 999, RD: true, QDCount: 2, ANCount: 2, NSCount: 10, ARCount: 5, Z: 3}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+% [2a] [2q] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, ANCount: 2, NSCount: 10, ARCount: 5, Z: 4}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [2a] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, QDCount: 1, ANCount: 2, NSCount: 10, ARCount: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [1q] [2a] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, QDCount: 2, ANCount: 1, NSCount: 10, ARCount: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [2q] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, QDCount: 1, ANCount: 0, NSCount: 10, ARCount: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [1q] [0a] [10n] [5au] (1234)"},

		{&layers.DNS{QR: true}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, AA: true, TC: true, Z: 2, QDCount: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0*-|$ 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 1, ResponseCode: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 inv_q FormErr- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 2, ResponseCode: 2}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 stat ServFail- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 3, ResponseCode: 3}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op3 NXDomain- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 4, ResponseCode: 4}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 notify NotImp- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 5, ResponseCode: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 update Refused- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 6, ResponseCode: 6}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op6 YXDomain- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 7, ResponseCode: 7}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op7 YXRRSet- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 8, ResponseCode: 8}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op8 NXRRSet- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 9, ResponseCode: 9}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateA NotAuth- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 10, ResponseCode: 10}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateD NotZone- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 11, ResponseCode: 11}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateDA Resp11- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 12, ResponseCode: 12}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateM Resp12- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 13, ResponseCode: 13}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateMA Resp13- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 14, ResponseCode: 14}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 zoneInit Resp14- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 15, ResponseCode: 15}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 zoneRef NoChange- [0q] 0/0/0 (1234)"},

		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 3}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 CH Unknown (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeNS, NS: []byte("nsteststring")}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 NS nsteststring. (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeMX, MX: layers.DNSMX{Name: []byte("mxteststring")}}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 MX mxteststring. 0 (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Type: layers.DNSTypeSRV, SRV: layers.DNSSRV{Name: []byte("srvteststring"), Port: 999, Priority: 2, Weight: 5}}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 Unknown SRV srvteststring.:999 2 5 (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeSOA}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 SOA (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeTXT, TXTs: [][]byte{[]byte("foo"), []byte("bar")}}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 TXT \"foo\" \"bar\" (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeHINFO}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 HINFO (1234)"},
	}

	for _, table := range tables {
		got := formatPacketDNS(table.dns, table.src, table.dst, table.srcPort, table.dstPort, table.length)
		if got != table.expected {
			t.Errorf("formatPacketDNS was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestFormat(t *testing.T) {
	tables := []struct {
		payload  []byte
		isIPv6   bool
		expected string
	}{
		{[]byte{0x45, 0x00, 0x00, 0x42, 0x9a, 0x66, 0x00, 0x00, 0x40, 0x11, 0xce, 0xc0, 0xc0, 0xa8, 0x48, 0x32, 0xc0, 0xa8, 0x48, 0x01, 0xfb, 0x6a, 0x00, 0x35, 0x00, 0x2e, 0x02, 0xeb, 0x29, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x73, 0x69, 0x67, 0x69, 0x6e, 0x74, 0x02, 0x63, 0x68, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false, "IP 192.168.72.50.64362 > 192.168.72.1.53: 10628+ [1au] A CH? sigint.ch. (38)"},
		{[]byte{0x45, 0x10, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xdc, 0xc5, 0xc0, 0xa8, 0x48, 0x32, 0xac, 0xd9, 0xa8, 0x2e, 0xe4, 0xd0, 0x00, 0x50, 0x20, 0x0d, 0x0d, 0x7a, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x5c, 0xd8, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0a, 0x32, 0xc6, 0x36, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}, false, "IP 192.168.72.50.58576 > 172.217.168.46.80: Flags [S], seq 537726330, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 851850963 ecr 0,sackOK,eol], length 0"},
		{[]byte{0x60, 0x0a, 0x8c, 0x43, 0x00, 0x2c, 0x06, 0xff, 0x2a, 0x01, 0x02, 0xa8, 0x85, 0x02, 0x1f, 0x01, 0x45, 0x38, 0x31, 0x33, 0x04, 0x0f, 0x0a, 0x2a, 0x2a, 0x00, 0x14, 0x50, 0x40, 0x0a, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e, 0xe4, 0xd1, 0x00, 0x50, 0x96, 0x3e, 0x44, 0x97, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0xec, 0x6e, 0x00, 0x00, 0x02, 0x04, 0x05, 0x98, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0a, 0x32, 0xc8, 0x5c, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}, true, "IP6 2a01:2a8:8502:1f01:4538:3133:40f:a2a.58577 > 2a00:1450:400a:802::200e.80: Flags [S], seq 2520663191, win 65535, options [mss 1432,nop,wscale 6,nop,nop,TS val 851991598 ecr 0,sackOK,eol], length 0"},
		{[]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0xc9, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0xdf, 0x70, 0xff, 0xfe, 0x6c, 0xa9, 0xd7, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x85, 0x80, 0x3a, 0x57, 0xab, 0x95, 0x6f, 0x00, 0x35, 0xf2, 0x84, 0x00, 0xc9, 0x40, 0x35, 0x58, 0xc2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0xf7, 0x00, 0x1b, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x2b, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x11, 0x6f, 0x00, 0x2f, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x0b, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x72, 0x65, 0x64, 0x69, 0x72, 0x06, 0x61, 0x6b, 0x61, 0x64, 0x6e, 0x73, 0xc0, 0x41, 0xc0, 0x52, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x09, 0x7d, 0x00, 0x19, 0x05, 0x65, 0x36, 0x38, 0x35, 0x38, 0x05, 0x64, 0x73, 0x63, 0x65, 0x39, 0x0a, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x41, 0xc0, 0x8d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x02, 0x14, 0xd6, 0xf3, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, true, "IP6 fe80::eadf:70ff:fe6c:a9d7.53 > fe80::885:803a:57ab:956f.62084: 22722 4/0/1 CNAME www.apple.com.edgekey.net., CNAME www.apple.com.edgekey.net.globalredir.akadns.net., CNAME e6858.dsce9.akamaiedge.net., A 2.20.214.243 (193)"},
		{[]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0xc9, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0xdf, 0x70, 0xff, 0xfe, 0x6c, 0xa9, 0xd7, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x85, 0x80, 0x3a, 0x57, 0xab, 0x95, 0x6f, 0x00, 0x35, 0xf2, 0x84, 0x00, 0xc9, 0x40, 0x35, 0x58, 0xc2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0xf7, 0x00, 0x1b, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x2b, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x11, 0x6f, 0x00, 0x2f, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x0b, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x72, 0x65, 0x64, 0x69, 0x72, 0x06, 0x61, 0x6b, 0x61, 0x64, 0x6e, 0x73, 0xc0, 0x41, 0xc0, 0x52, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x09, 0x7d, 0x00, 0x19, 0x05, 0x65, 0x36, 0x38, 0x35, 0x38, 0x05, 0x64, 0x73, 0x63, 0x65, 0x39, 0x0a, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x41, 0xc0, 0x8d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x02, 0x14, 0xd6, 0xf3, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, true, "IP6 fe80::eadf:70ff:fe6c:a9d7.53 > fe80::885:803a:57ab:956f.62084: 22722 4/0/1 CNAME www.apple.com.edgekey.net., CNAME www.apple.com.edgekey.net.globalredir.akadns.net., CNAME e6858.dsce9.akamaiedge.net., A 2.20.214.243 (193)"},
		{[]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xb3, 0xf9, 0xdc, 0xd0, 0x6a, 0x53, 0xc5, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x3a, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x8f, 0x00, 0x49, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb}, true, "IP6 fe80::10b3:f9dc:d06a:53c5 > ff02::16: ICMP6, length 36"},
		{[]byte{0x6c, 0x05, 0x41, 0x6d, 0x00, 0x28, 0x59, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x0a, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x28, 0x0a, 0x0a, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xae, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x13, 0x00, 0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x0b}, true, "IP6 fe80::a0a:a0a > ff02::5: OSPFv3, Hello, length 40"},
		{[]byte{0x45, 0x00, 0x00, 0x54, 0xee, 0x0a, 0x00, 0x00, 0x40, 0x01, 0x82, 0xc3, 0xc0, 0xa8, 0x48, 0x32, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x5e, 0x47, 0xc3, 0x28, 0x00, 0x00, 0x5b, 0xe8, 0x50, 0xec, 0x00, 0x07, 0x3e, 0xb1, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}, false, "IP 192.168.72.50 > 1.0.0.1: ICMP echo request, id 49960, seq 0, length 64"},
		{[]byte{0x46, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x01, 0x02, 0xfb, 0xed, 0xc0, 0xa8, 0x48, 0x23, 0xe0, 0x00, 0x00, 0x16, 0x94, 0x04, 0x00, 0x00, 0x22, 0x00, 0xf9, 0x02, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0xfb}, false, "IP 192.168.72.35 > 224.0.0.22: IGMP, length 16"},
	}

	for _, table := range tables {
		var packet gopacket.Packet
		if table.isIPv6 {
			packet = gopacket.NewPacket(table.payload, layers.LayerTypeIPv6, gopacket.Default)
		} else {
			packet = gopacket.NewPacket(table.payload, layers.LayerTypeIPv4, gopacket.Default)
		}
		got := Format(packet)
		if got != table.expected {
			t.Errorf("Format was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}