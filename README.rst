NFTRACE
=======
Easier tracing of packets through iptables

Also WARNING this will probably burn your house down

Example
-------
Using laptop workstation with most rules managed by ``firewalld``

.. code:: bash

  # This will only capture dns reply from 8.8.8.8 packets for this example
  [eiginn:~]$ sudo iptables -t raw -I PREROUTING -p udp -m udp -s 8.8.8.8 --sport 53 -j TRACE

  # In another terminal, get ready to run
  [eiginn:~]$ dig @8.8.8.8 google.com
  # run nftrace and then dig command
  [eiginn:~]$ sudo nftrace
  2020/04/28 21:48:59 Trying to acquire the lock: /run/xtables.lock
  TRACE: raw:PREROUTING:rule:2  "-A PREROUTING -j PREROUTING_direct"
  TRACE: raw:PREROUTING_direct:return:1
  TRACE: raw:PREROUTING:rule:3  "-A PREROUTING -j PREROUTING_ZONES"
  TRACE: raw:PREROUTING_ZONES:rule:3  "-A PREROUTING_ZONES -i wlp61s0 -g PRE_home"
  TRACE: raw:PRE_home:rule:1  "-A PRE_home -j PRE_home_pre"
  TRACE: raw:PRE_home_pre:return:1
  TRACE: raw:PRE_home:rule:2  "-A PRE_home -j PRE_home_log"
  TRACE: raw:PRE_home_log:return:1
  TRACE: raw:PRE_home:rule:3  "-A PRE_home -j PRE_home_deny"
  TRACE: raw:PRE_home_deny:return:1
  TRACE: raw:PRE_home:rule:4  "-A PRE_home -j PRE_home_allow"
  TRACE: raw:PRE_home_allow:return:2
  TRACE: raw:PRE_home:rule:5  "-A PRE_home -j PRE_home_post"
  TRACE: raw:PRE_home_post:return:1
  TRACE: raw:PRE_home:return:6
  TRACE: raw:PREROUTING:policy:4  "-P PREROUTING ACCEPT"
  TRACE: mangle:PREROUTING:rule:1  "-A PREROUTING -j PREROUTING_direct"
  TRACE: mangle:PREROUTING_direct:return:1
  TRACE: mangle:PREROUTING:rule:2  "-A PREROUTING -j PREROUTING_ZONES"
  TRACE: mangle:PREROUTING_ZONES:rule:3  "-A PREROUTING_ZONES -i wlp61s0 -g PRE_home"
  TRACE: mangle:PRE_home:rule:1  "-A PRE_home -j PRE_home_pre"
  TRACE: mangle:PRE_home_pre:return:1
  TRACE: mangle:PRE_home:rule:2  "-A PRE_home -j PRE_home_log"
  TRACE: mangle:PRE_home_log:return:1
  TRACE: mangle:PRE_home:rule:3  "-A PRE_home -j PRE_home_deny"
  TRACE: mangle:PRE_home_deny:return:1
  TRACE: mangle:PRE_home:rule:4  "-A PRE_home -j PRE_home_allow"
  TRACE: mangle:PRE_home_allow:return:1
  TRACE: mangle:PRE_home:rule:5  "-A PRE_home -j PRE_home_post"
  TRACE: mangle:PRE_home_post:return:1
  TRACE: mangle:PRE_home:return:6
  TRACE: mangle:PREROUTING:policy:3  "-P PREROUTING ACCEPT"
  TRACE: mangle:INPUT:rule:1  "-A INPUT -j INPUT_direct"
  TRACE: mangle:INPUT_direct:return:1
  TRACE: mangle:INPUT:policy:2  "-P INPUT ACCEPT"
  TRACE: filter:INPUT:rule:1  "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT"
  TRACE: security:INPUT:rule:1  "-A INPUT -j INPUT_direct"
  TRACE: security:INPUT_direct:return:1
  TRACE: security:INPUT:policy:2  "-P INPUT ACCEPT"


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

- sanity check that ``nfnetlink_log`` is registered or nothing will be received
- IPv6 should not be difficult to add
- Coalescing of events by packet:
  possibly take payload of log msg (first N bytes of packet), hash it, pass something that will buffer then flush after some time.
- TRACE rule adding/removing
