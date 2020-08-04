NFTRACE
=======
Easier tracing of packets through iptables

Also WARNING this will probably burn your house down

Example
-------
Using laptop workstation with most rules managed by ``firewalld``

.. code:: bash

  # Need two TRACE rules to capture flows in both directions
  [eiginn:~]$ sudo iptables -t raw -I OUTPUT -p udp -m udp --dport 53 -j TRACE
  [eiginn:~]$ sudo iptables -t raw -I PREROUTING -p udp -m udp --sport 53 -j TRACE

  # In another terminal, get ready to run
  [eiginn:~]$ dig @8.8.8.8 google.com

  # run nftrace and then dig command
  [eiginn:~]$ sudo nftrace -4
  2020/08/03 18:13:10 Assuming TRACE rule(s) handled seperately
  324792e67d8a TRACE: raw:OUTPUT:rule:2  "-A OUTPUT -j OUTPUT_direct"
  324792e67d8a TRACE: raw:OUTPUT_direct:return:1
  324792e67d8a TRACE: raw:OUTPUT:policy:3  "-P OUTPUT ACCEPT"
  324792e67d8a TRACE: mangle:OUTPUT:rule:1  "-A OUTPUT -j OUTPUT_direct"
  324792e67d8a TRACE: mangle:OUTPUT_direct:return:1
  324792e67d8a TRACE: mangle:OUTPUT:policy:2  "-P OUTPUT ACCEPT"
  324792e67d8a TRACE: nat:OUTPUT:rule:1  "-A OUTPUT -j OUTPUT_direct"
  324792e67d8a TRACE: nat:OUTPUT_direct:return:1
  324792e67d8a TRACE: nat:OUTPUT:policy:3  "-P OUTPUT ACCEPT"
  324792e67d8a TRACE: filter:OUTPUT:rule:1  "-A OUTPUT -j LIBVIRT_OUT"
  324792e67d8a TRACE: filter:LIBVIRT_OUT:return:5
  324792e67d8a TRACE: filter:OUTPUT:rule:3  "-A OUTPUT -j OUTPUT_direct"
  324792e67d8a TRACE: filter:OUTPUT_direct:return:1
  324792e67d8a TRACE: filter:OUTPUT:policy:4  "-P OUTPUT ACCEPT"
  324792e67d8a TRACE: security:OUTPUT:rule:1  "-A OUTPUT -j OUTPUT_direct"
  324792e67d8a TRACE: security:OUTPUT_direct:return:1
  324792e67d8a TRACE: security:OUTPUT:policy:2  "-P OUTPUT ACCEPT"
  324792e67d8a TRACE: mangle:POSTROUTING:rule:1  "-A POSTROUTING -j LIBVIRT_PRT"
  324792e67d8a TRACE: mangle:LIBVIRT_PRT:return:2
  324792e67d8a TRACE: mangle:POSTROUTING:rule:2  "-A POSTROUTING -j POSTROUTING_direct"
  324792e67d8a TRACE: mangle:POSTROUTING_direct:return:1
  324792e67d8a TRACE: mangle:POSTROUTING:policy:3  "-P POSTROUTING ACCEPT"
  324792e67d8a TRACE: nat:POSTROUTING:rule:1  "-A POSTROUTING -j ts-postrouting"
  324792e67d8a TRACE: nat:ts-postrouting:return:2
  324792e67d8a TRACE: nat:POSTROUTING:rule:3  "-A POSTROUTING -j LIBVIRT_PRT"
  324792e67d8a TRACE: nat:LIBVIRT_PRT:return:6
  324792e67d8a TRACE: nat:POSTROUTING:rule:4  "-A POSTROUTING -j POSTROUTING_direct"
  324792e67d8a TRACE: nat:POSTROUTING_direct:return:1
  324792e67d8a TRACE: nat:POSTROUTING:rule:5  "-A POSTROUTING -j POSTROUTING_ZONES"
  324792e67d8a TRACE: nat:POSTROUTING_ZONES:rule:1  "-A POSTROUTING_ZONES -o wlp61s0 -g POST_home"
  324792e67d8a TRACE: nat:POST_home:rule:1  "-A POST_home -j POST_home_pre"
  324792e67d8a TRACE: nat:POST_home_pre:return:1
  324792e67d8a TRACE: nat:POST_home:rule:2  "-A POST_home -j POST_home_log"
  324792e67d8a TRACE: nat:POST_home_log:return:1
  324792e67d8a TRACE: nat:POST_home:rule:3  "-A POST_home -j POST_home_deny"
  324792e67d8a TRACE: nat:POST_home_deny:return:1
  324792e67d8a TRACE: nat:POST_home:rule:4  "-A POST_home -j POST_home_allow"
  324792e67d8a TRACE: nat:POST_home_allow:return:1
  324792e67d8a TRACE: nat:POST_home:rule:5  "-A POST_home -j POST_home_post"
  324792e67d8a TRACE: nat:POST_home_post:return:1
  324792e67d8a TRACE: nat:POST_home:return:6
  324792e67d8a TRACE: nat:POSTROUTING:policy:6  "-P POSTROUTING ACCEPT"
  4fbdc33389d9 TRACE: raw:PREROUTING:rule:2  "-A PREROUTING -j PREROUTING_direct"
  4fbdc33389d9 TRACE: raw:PREROUTING_direct:return:1
  4fbdc33389d9 TRACE: raw:PREROUTING:rule:3  "-A PREROUTING -j PREROUTING_ZONES"
  4fbdc33389d9 TRACE: raw:PREROUTING_ZONES:rule:1  "-A PREROUTING_ZONES -i wlp61s0 -g PRE_home"
  4fbdc33389d9 TRACE: raw:PRE_home:rule:1  "-A PRE_home -j PRE_home_pre"
  4fbdc33389d9 TRACE: raw:PRE_home_pre:return:1
  4fbdc33389d9 TRACE: raw:PRE_home:rule:2  "-A PRE_home -j PRE_home_log"
  4fbdc33389d9 TRACE: raw:PRE_home_log:return:1
  4fbdc33389d9 TRACE: raw:PRE_home:rule:3  "-A PRE_home -j PRE_home_deny"
  4fbdc33389d9 TRACE: raw:PRE_home_deny:return:1
  4fbdc33389d9 TRACE: raw:PRE_home:rule:4  "-A PRE_home -j PRE_home_allow"
  4fbdc33389d9 TRACE: raw:PRE_home_allow:return:2
  4fbdc33389d9 TRACE: raw:PRE_home:rule:5  "-A PRE_home -j PRE_home_post"
  4fbdc33389d9 TRACE: raw:PRE_home_post:return:1
  4fbdc33389d9 TRACE: raw:PRE_home:return:6
  4fbdc33389d9 TRACE: raw:PREROUTING:policy:4  "-P PREROUTING ACCEPT"
  4fbdc33389d9 TRACE: mangle:PREROUTING:rule:1  "-A PREROUTING -j PREROUTING_direct"
  4fbdc33389d9 TRACE: mangle:PREROUTING_direct:return:1
  4fbdc33389d9 TRACE: mangle:PREROUTING:rule:2  "-A PREROUTING -j PREROUTING_ZONES"
  4fbdc33389d9 TRACE: mangle:PREROUTING_ZONES:rule:1  "-A PREROUTING_ZONES -i wlp61s0 -g PRE_home"
  4fbdc33389d9 TRACE: mangle:PRE_home:rule:1  "-A PRE_home -j PRE_home_pre"
  4fbdc33389d9 TRACE: mangle:PRE_home_pre:return:1
  4fbdc33389d9 TRACE: mangle:PRE_home:rule:2  "-A PRE_home -j PRE_home_log"
  4fbdc33389d9 TRACE: mangle:PRE_home_log:return:1
  4fbdc33389d9 TRACE: mangle:PRE_home:rule:3  "-A PRE_home -j PRE_home_deny"
  4fbdc33389d9 TRACE: mangle:PRE_home_deny:return:1
  4fbdc33389d9 TRACE: mangle:PRE_home:rule:4  "-A PRE_home -j PRE_home_allow"
  4fbdc33389d9 TRACE: mangle:PRE_home_allow:return:1
  4fbdc33389d9 TRACE: mangle:PRE_home:rule:5  "-A PRE_home -j PRE_home_post"
  4fbdc33389d9 TRACE: mangle:PRE_home_post:return:1
  4fbdc33389d9 TRACE: mangle:PRE_home:return:6
  4fbdc33389d9 TRACE: mangle:PREROUTING:policy:3  "-P PREROUTING ACCEPT"
  4fbdc33389d9 TRACE: mangle:INPUT:rule:1  "-A INPUT -j INPUT_direct"
  4fbdc33389d9 TRACE: mangle:INPUT_direct:return:1
  4fbdc33389d9 TRACE: mangle:INPUT:policy:2  "-P INPUT ACCEPT"
  4fbdc33389d9 TRACE: filter:INPUT:rule:1  "-A INPUT -j ts-input"
  4fbdc33389d9 TRACE: filter:ts-input:return:4
  4fbdc33389d9 TRACE: filter:INPUT:rule:2  "-A INPUT -j LIBVIRT_INP"
  4fbdc33389d9 TRACE: filter:LIBVIRT_INP:return:5
  4fbdc33389d9 TRACE: filter:INPUT:rule:3  "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT"
  4fbdc33389d9 TRACE: security:INPUT:rule:1  "-A INPUT -j INPUT_direct"
  4fbdc33389d9 TRACE: security:INPUT_direct:return:1
  4fbdc33389d9 TRACE: security:INPUT:policy:2  "-P INPUT ACCEPT"
  ^C
  Aggregated packets:
  324792e67d8a PACKET: 79 bytes
  - Layer 1 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..59..] Version=4 IHL=5 TOS=0 Length=79 Id=8293 Flags= FragOffset=0 TTL=64 Protocol=UDP Checksum=16314 SrcIP=192.168.1.112 DstIP=8.8.8.8 Options=[] Padding=[]}
  - Layer 2 (08 bytes) = UDP      {Contents=[..8..] Payload=[..51..] SrcPort=57779 DstPort=53(domain) Length=59 Checksum=8133}
  - Layer 3 (51 bytes) = DNS      {Contents=[..51..] Payload=[] ID=39540 QR=false OpCode=Query AA=false TC=false RD=true RA=false Z=2 ResponseCode=No Error QDCount=1 ANCount=0 NSCount=0 ARCount=1 Questions=[{Name=[..10..] Type=A Class=IN}] Answers=[] Authorities=[] Additionals=[{Name=[] Type=OPT Class=Unknown TTL=0 DataLength=12 Data=[..12..] IP=<nil> NS=[] CNAME=[] PTR=[] TXTs=[] SOA={ MName=[] RName=[] Serial=0 Refresh=0 Retry=0 Expire=0 Minimum=0} SRV={ Priority=0 Weight=0 Port=0 Name=[]} MX={ Preference=0 Name=[]} OPT=[Cookie=d271a694a95bc98b] TXT=[]}]}
  
  4fbdc33389d9 PACKET: 83 bytes
  - Layer 1 (20 bytes) = IPv4     {Contents=[..20..] Payload=[..63..] Version=4 IHL=5 TOS=32 Length=83 Id=31227 Flags= FragOffset=0 TTL=122 Protocol=UDP Checksum=44031 SrcIP=8.8.8.8 DstIP=192.168.1.112 Options=[] Padding=[]}
  - Layer 2 (08 bytes) = UDP      {Contents=[..8..] Payload=[..55..] SrcPort=53(domain) DstPort=57779 Length=63 Checksum=20111}
  - Layer 3 (55 bytes) = DNS      {Contents=[..55..] Payload=[] ID=39540 QR=true OpCode=Query AA=false TC=false RD=true RA=true Z=0 ResponseCode=No Error QDCount=1 ANCount=1 NSCount=0 ARCount=1 Questions=[{Name=[..10..] Type=A Class=IN}] Answers=[{Name=[..10..] Type=A Class=IN TTL=298 DataLength=4 Data=[216, 58, 195, 78] IP=216.58.195.78 NS=[] CNAME=[] PTR=[] TXTs=[] SOA={ MName=[] RName=[] Serial=0 Refresh=0 Retry=0 Expire=0 Minimum=0} SRV={ Priority=0 Weight=0 Port=0 Name=[]} MX={ Preference=0 Name=[]} OPT=[] TXT=[]}] Authorities=[] Additionals=[{Name=[] Type=OPT Class=Unknown TTL=0 DataLength=0 Data=[] IP=<nil> NS=[] CNAME=[] PTR=[] TXTs=[] SOA={ MName=[] RName=[] Serial=0 Refresh=0 Retry=0 Expire=0 Minimum=0} SRV={ Priority=0 Weight=0 Port=0 Name=[]} MX={ Preference=0 Name=[]} OPT=[] TXT=[]}]}
  


Why
---
nftables has ``xtables-monitor`` which only works for packets while processed by nftables and I got really tired of debugging kubernetes/calico rules getting everything shoved out to the console. Additionally, nftrace will hold the xtables lock for the duration of the run, so if you're fighting with k8s/calico moving your TRACE rule around, this will help.

(You should understand the ramifications of pausing all firewall updates before running this)

Previously to keep rule set stable for a short capture I would run something like:

.. code:: bash

  root@somenode:~# set -x ; iptables -t raw -I PREROUTING -i caliae52921e040 -j TRACE && iptables -t raw -I OUTPUT -d 8.8.8.8 -j TRACE && flock /run/xtables.lock sleep 20 && iptables -t raw -D PREROUTING -i caliae52921e040 -j TRACE && iptables -t raw -D OUTPUT -d 8.8.8.8 -j TRACE; set +x
  + iptables -t raw -I PREROUTING -i caliae52921e040 -j TRACE
  + iptables -t raw -I OUTPUT -d 8.8.8.8 -j TRACE
  + flock /run/xtables.lock sleep 20
  + iptables -t raw -D PREROUTING -i caliae52921e040 -j TRACE
  + iptables -t raw -D OUTPUT -d 8.8.8.8 -j TRACE
  + set +x
  root@somenode:~#


Prerequisites
-------------

``nfnetlink_log`` as the registered logger for address family (inet/inet6), this may be a deal breaker for some depending on your use of ``(|U|NF)LOG`` targets.

.. code:: bash

  cat /proc/net/netfilter/nf_log
   0 nfnetlink_log (nfnetlink_log)
   1 NONE (nfnetlink_log)
   2 nfnetlink_log (nf_log_ipv4,nfnetlink_log)
   3 NONE (nfnetlink_log)
   4 NONE (nfnetlink_log)
   5 NONE (nfnetlink_log)
   6 NONE (nfnetlink_log)
   7 NONE (nfnetlink_log)
   8 NONE (nfnetlink_log)
   9 NONE (nfnetlink_log)
  10 NONE (nfnetlink_log)
  11 NONE (nfnetlink_log)
  12 NONE (nfnetlink_log)


TODO
----

- How to handle bidirectional flows? right now its unidirectional unless TRACE rules are handled separately
- Inject comment "match" into nftrace handled rules to make obvious where the rule came from.

Alternative Ideas
-----------------

You don't need this tool to get similar results, though looking up the matching rule would be a pain imo.

Enter nflog+tshark, this still uses ``nfnetlink_log`` as before, except we're going to capture using nflog interface on group 0 ``-i nflog:0``

.. code:: bash

  # change what fields you display to your heart's content
  [eiginn:~]$ ( sudo timeout 30 tshark -i nflog:0 -Tfields -Eheader=y -Eseparator=\| -e nflog.prefix -e ip -e dns; ) | column -t -s \|
  Running as user "root" and group "root". This could be dangerous.
  Capturing on 'nflog:0'
  39
  nflog.prefix                                ip                                                             dns
  TRACE: raw:PREROUTING:rule:2                Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PREROUTING_direct:return:1       Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PREROUTING:rule:3                Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PREROUTING_ZONES:rule:1          Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal:rule:1              Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal_pre:return:1        Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal:rule:2              Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal_log:return:1        Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal:rule:3              Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal_deny:return:1       Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal:rule:4              Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal_allow:return:2      Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal:rule:5              Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal_post:return:1       Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PRE_internal:return:6            Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: raw:PREROUTING:policy:4              Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PREROUTING:rule:1             Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PREROUTING_direct:return:1    Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PREROUTING:rule:2             Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PREROUTING_ZONES:rule:1       Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal:rule:1           Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal_pre:return:1     Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal:rule:2           Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal_log:return:1     Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal:rule:3           Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal_deny:return:1    Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal:rule:4           Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal_allow:return:1   Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal:rule:5           Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal_post:return:1    Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PRE_internal:return:6         Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:PREROUTING:policy:3           Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:INPUT:rule:1                  Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:INPUT_direct:return:1         Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: mangle:INPUT:policy:2                Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: filter:INPUT:rule:1                  Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: security:INPUT:rule:1                Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: security:INPUT_direct:return:1       Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)
  TRACE: security:INPUT:policy:2              Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.1.102  Domain Name System (response)

You can also take a regular pcap of this and load it into wireshark and add ``nflog.prefix`` as a column
