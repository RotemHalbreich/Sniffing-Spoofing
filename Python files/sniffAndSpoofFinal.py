#!/bin/bin/python
from scapy.all import *
def send_pkt(pkt):
	a = IP()
	a.src = pkt[IP].dst			
	a.dst = pkt[IP].src		
	b = ICMP()
	b.type ="echo-reply"
	b.code =0
	b.id = pkt[ICMP].id
	b.seq = pkt[ICMP].seq
	p = a/b
	send(p)

pkt = sniff(filter='icmp[icmptype] == icmp-echo', prn=send_pkt)
