NFTRACE
=======
Easier tracing of packets through iptables

Installation
------------

.. code:: bash

  go get -u -v github.com/eiginn/nftrace/cmd/nftrace


Examples
-------
Quick and contrived example: "Weird, udp dns queries to 8.8.8.8 work and yet 8.8.4.4 is timing out, how odd" :)

.. code:: bash

  root@92ea2d329032:/# ./nftrace -p'-s 8.8.4.4'
  2020/10/02 20:28:43 Adding rule: -t raw -I PREROUTING -s 8.8.4.4 -j TRACE
  333e26bf278d TRACE: raw:PREROUTING:rule:3  "-A PREROUTING -s 8.8.4.4/32 -p udp -m udp --sport 53 -j MARK --set-xmark 0xef/0xffffffff"
  333e26bf278d TRACE: raw:PREROUTING:policy:4  "-P PREROUTING ACCEPT"
  333e26bf278d TRACE: filter:INPUT:rule:1  "-A INPUT -m mark --mark 0xef -j DROP"

  Aggregated packets:
  333e26bf278d IP 8.8.4.4.53 > 172.20.0.2.37784: 31439 1/0/1 A 216.58.195.78 (55)

  2020/10/02 20:29:13 Removing rule: -t raw -A PREROUTING -s 8.8.4.4 -j TRACE

Using laptop workstation with most rules managed by ``firewalld``

.. code:: bash

  # In another terminal, get ready to run
  [eiginn:~]$ ping -6 -n -c 1 2001:4860:4860::8888

  # run nftrace and then ping command
  [eiginn:~]$ sudo nftrace -6 -p'-s 2001:4860:4860::8888/128 -p ipv6-icmp' -o'-d 2001:4860:4860::8888/128 -p ipv6-icmp'
  2020/10/02 19:56:02 Adding rule: -t raw -I PREROUTING -s 2001:4860:4860::8888/128 -p ipv6-icmp -j TRACE
  2020/10/02 19:56:02 Adding rule: -t raw -I OUTPUT -d 2001:4860:4860::8888/128 -p ipv6-icmp -j TRACE
  97f031f9d7f1 TRACE: raw:OUTPUT:rule:2  "-A OUTPUT -j OUTPUT_direct"
  97f031f9d7f1 TRACE: raw:OUTPUT_direct:return:1
  97f031f9d7f1 TRACE: raw:OUTPUT:policy:3  "-P OUTPUT ACCEPT"
  97f031f9d7f1 TRACE: mangle:OUTPUT:rule:1  "-A OUTPUT -j OUTPUT_direct"
  97f031f9d7f1 TRACE: mangle:OUTPUT_direct:return:1
  97f031f9d7f1 TRACE: mangle:OUTPUT:policy:2  "-P OUTPUT ACCEPT"
  97f031f9d7f1 TRACE: nat:OUTPUT:rule:1  "-A OUTPUT -j OUTPUT_direct"
  97f031f9d7f1 TRACE: nat:OUTPUT_direct:return:1
  97f031f9d7f1 TRACE: nat:OUTPUT:policy:2  "-P OUTPUT ACCEPT"
  97f031f9d7f1 TRACE: filter:OUTPUT:rule:1  "-A OUTPUT -j LIBVIRT_OUT"
  97f031f9d7f1 TRACE: filter:LIBVIRT_OUT:return:1
  97f031f9d7f1 TRACE: filter:OUTPUT:rule:3  "-A OUTPUT -j OUTPUT_direct"
  97f031f9d7f1 TRACE: filter:OUTPUT_direct:return:1
  97f031f9d7f1 TRACE: filter:OUTPUT:rule:4  "-A OUTPUT -j RFC3964_IPv4"
  97f031f9d7f1 TRACE: filter:RFC3964_IPv4:return:19
  97f031f9d7f1 TRACE: filter:OUTPUT:policy:5  "-P OUTPUT ACCEPT"
  97f031f9d7f1 TRACE: security:OUTPUT:rule:1  "-A OUTPUT -p ipv6-icmp -m comment --comment \"wouldn\\'t you have liked to know this rule was hit?\""
  97f031f9d7f1 TRACE: security:OUTPUT:rule:2  "-A OUTPUT -j OUTPUT_direct"
  97f031f9d7f1 TRACE: security:OUTPUT_direct:return:1
  97f031f9d7f1 TRACE: security:OUTPUT:policy:3  "-P OUTPUT ACCEPT"
  97f031f9d7f1 TRACE: mangle:POSTROUTING:rule:1  "-A POSTROUTING -j LIBVIRT_PRT"
  97f031f9d7f1 TRACE: mangle:LIBVIRT_PRT:return:1
  97f031f9d7f1 TRACE: mangle:POSTROUTING:rule:2  "-A POSTROUTING -j POSTROUTING_direct"
  97f031f9d7f1 TRACE: mangle:POSTROUTING_direct:return:1
  97f031f9d7f1 TRACE: mangle:POSTROUTING:policy:3  "-P POSTROUTING ACCEPT"
  97f031f9d7f1 TRACE: nat:POSTROUTING:rule:1  "-A POSTROUTING -j LIBVIRT_PRT"
  97f031f9d7f1 TRACE: nat:LIBVIRT_PRT:return:1
  97f031f9d7f1 TRACE: nat:POSTROUTING:rule:2  "-A POSTROUTING -j POSTROUTING_direct"
  97f031f9d7f1 TRACE: nat:POSTROUTING_direct:return:1
  97f031f9d7f1 TRACE: nat:POSTROUTING:rule:3  "-A POSTROUTING -j POSTROUTING_ZONES"
  97f031f9d7f1 TRACE: nat:POSTROUTING_ZONES:rule:1  "-A POSTROUTING_ZONES -o wlp61s0 -g POST_home"
  97f031f9d7f1 TRACE: nat:POST_home:rule:1  "-A POST_home -j POST_home_pre"
  97f031f9d7f1 TRACE: nat:POST_home_pre:return:1
  97f031f9d7f1 TRACE: nat:POST_home:rule:2  "-A POST_home -j POST_home_log"
  97f031f9d7f1 TRACE: nat:POST_home_log:return:1
  97f031f9d7f1 TRACE: nat:POST_home:rule:3  "-A POST_home -j POST_home_deny"
  97f031f9d7f1 TRACE: nat:POST_home_deny:return:1
  97f031f9d7f1 TRACE: nat:POST_home:rule:4  "-A POST_home -j POST_home_allow"
  97f031f9d7f1 TRACE: nat:POST_home_allow:return:1
  97f031f9d7f1 TRACE: nat:POST_home:rule:5  "-A POST_home -j POST_home_post"
  97f031f9d7f1 TRACE: nat:POST_home_post:return:1
  97f031f9d7f1 TRACE: nat:POST_home:return:6
  97f031f9d7f1 TRACE: nat:POSTROUTING:policy:4  "-P POSTROUTING ACCEPT"
  36c479892f1c TRACE: raw:PREROUTING:rule:2  "-A PREROUTING -j PREROUTING_direct"
  36c479892f1c TRACE: raw:PREROUTING_direct:return:1
  36c479892f1c TRACE: raw:PREROUTING:rule:3  "-A PREROUTING -j PREROUTING_ZONES"
  36c479892f1c TRACE: raw:PREROUTING_ZONES:rule:1  "-A PREROUTING_ZONES -i wlp61s0 -g PRE_home"
  36c479892f1c TRACE: raw:PRE_home:rule:1  "-A PRE_home -j PRE_home_pre"
  36c479892f1c TRACE: raw:PRE_home_pre:return:1
  36c479892f1c TRACE: raw:PRE_home:rule:2  "-A PRE_home -j PRE_home_log"
  36c479892f1c TRACE: raw:PRE_home_log:return:1
  36c479892f1c TRACE: raw:PRE_home:rule:3  "-A PRE_home -j PRE_home_deny"
  36c479892f1c TRACE: raw:PRE_home_deny:return:1
  36c479892f1c TRACE: raw:PRE_home:rule:4  "-A PRE_home -j PRE_home_allow"
  36c479892f1c TRACE: raw:PRE_home_allow:return:1
  36c479892f1c TRACE: raw:PRE_home:rule:5  "-A PRE_home -j PRE_home_post"
  36c479892f1c TRACE: raw:PRE_home_post:return:1
  36c479892f1c TRACE: raw:PRE_home:return:6
  36c479892f1c TRACE: raw:PREROUTING:policy:4  "-P PREROUTING ACCEPT"
  36c479892f1c TRACE: mangle:PREROUTING:rule:1  "-A PREROUTING -j PREROUTING_direct"
  36c479892f1c TRACE: mangle:PREROUTING_direct:return:1
  36c479892f1c TRACE: mangle:PREROUTING:rule:2  "-A PREROUTING -j PREROUTING_ZONES"
  36c479892f1c TRACE: mangle:PREROUTING_ZONES:rule:1  "-A PREROUTING_ZONES -i wlp61s0 -g PRE_home"
  36c479892f1c TRACE: mangle:PRE_home:rule:1  "-A PRE_home -j PRE_home_pre"
  36c479892f1c TRACE: mangle:PRE_home_pre:return:1
  36c479892f1c TRACE: mangle:PRE_home:rule:2  "-A PRE_home -j PRE_home_log"
  36c479892f1c TRACE: mangle:PRE_home_log:return:1
  36c479892f1c TRACE: mangle:PRE_home:rule:3  "-A PRE_home -j PRE_home_deny"
  36c479892f1c TRACE: mangle:PRE_home_deny:return:1
  36c479892f1c TRACE: mangle:PRE_home:rule:4  "-A PRE_home -j PRE_home_allow"
  36c479892f1c TRACE: mangle:PRE_home_allow:return:1
  36c479892f1c TRACE: mangle:PRE_home:rule:5  "-A PRE_home -j PRE_home_post"
  36c479892f1c TRACE: mangle:PRE_home_post:return:1
  36c479892f1c TRACE: mangle:PRE_home:return:6
  36c479892f1c TRACE: mangle:PREROUTING:policy:3  "-P PREROUTING ACCEPT"
  36c479892f1c TRACE: mangle:INPUT:rule:1  "-A INPUT -j INPUT_direct"
  36c479892f1c TRACE: mangle:INPUT_direct:return:1
  36c479892f1c TRACE: mangle:INPUT:policy:2  "-P INPUT ACCEPT"
  36c479892f1c TRACE: filter:INPUT:rule:2  "-A INPUT -j LIBVIRT_INP"
  36c479892f1c TRACE: filter:LIBVIRT_INP:return:1
  36c479892f1c TRACE: filter:INPUT:rule:3  "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT"
  36c479892f1c TRACE: security:INPUT:rule:1  "-A INPUT -j INPUT_direct"
  36c479892f1c TRACE: security:INPUT_direct:return:1
  36c479892f1c TRACE: security:INPUT:policy:2  "-P INPUT ACCEPT"

  Aggregated packets:
  97f031f9d7f1 IP6 2601:645:500:d6::4 > 2001:4860:4860::8888: ICMP6, echo request, id 8, seq 1, length 64
  36c479892f1c IP6 2001:4860:4860::8888 > 2001:4860:4860::8888::4: ICMP6, echo reply, id 8, seq 1, length 64

  2020/10/02 19:56:07 Removing rule: -t raw -A OUTPUT -d 2001:4860:4860::8888/128 -p ipv6-icmp -j TRACE
  2020/10/02 19:56:07 Removing rule: -t raw -A PREROUTING -s 2001:4860:4860::8888/128 -p ipv6-icmp -j TRACE


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


Warnings
--------
Caution should be taken when making any kind of firewall changes, especially involving the TRACE target.
I have seen machines become unresponsive and basically fall off the network due trace rules that were not carefully chosen to limit how often they are hit.

A timeout of 30s is default to make some attempt to recover if your session hangs, see also using the limit option.


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
