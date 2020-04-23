module github.com/eiginn/nftrace

go 1.14

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/coreos/go-iptables v0.4.5
	github.com/florianl/go-nflog v1.1.0
	github.com/google/gopacket v1.1.17
	github.com/mdlayher/netlink v1.1.0 // indirect
	golang.org/x/net v0.0.0-20200421231249-e086a090c8fd // indirect
	golang.org/x/sys v0.0.0-20200420163511-1957bb5e6d1f // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace github.com/florianl/go-nflog => /home/vaelen/repos_priv/go-nflog
