#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
        int i =0;
        int size_data=0;
	printf("\n Got TCP packet!\n");
	struct ethheader *eth=(struct ethheader *)packet;
	struct sockaddr_in ip_src, ip_dst;
	struct iphdr *ip = (struct iphdr *)(packet + 14);

	
		printf("----Sniffed packet----\n");
	
		

	ip_src.sin_addr.s_addr = ip->saddr;
	printf("Src IP: %s \n", inet_ntoa(ip_src.sin_addr));

	ip_dst.sin_addr.s_addr = ip->daddr;
	printf("Dst IP: %s \n", inet_ntoa(ip_dst.sin_addr));

	//struct icmphdr *icmp = (struct icmphdr *)(packet + (ip->ihl * 4) + 14);
	char *data =(u_char *)packet + 14 + sizeof(struct iphdr) +sizeof(struct tcphdr );
	size_data=ntohs(ip->tot_len) - (sizeof(struct iphdr) +sizeof(struct tcphdr ));
	if(size_data>0){
	printf(" Payload (%d bytes): \n" , size_data);
	for(i=0;i<size_data; i ++){
	if( isprint(*data))
	printf("%c", *data);
	else
	printf(".");
	
	data++;
	}
	}

	
}

int main()
{
	printf("Waiting for TCP packet...\n\n");

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "proto TCP and dst portrange 10-100";
	bpf_u_int32 net;

	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	
	return 0;
}
