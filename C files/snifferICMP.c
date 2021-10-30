
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


int count =0;
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	printf("Got an ICMP packet!\n");
	struct sockaddr_in ip_src, ip_dst;
	struct iphdr *ip = (struct iphdr *)(packet + 14);
           if (count %2==0){

		printf("-----Request-----\n");
		}
		else  printf("-----Reply-----\n");
	
	ip_src.sin_addr.s_addr = ip->saddr;
	printf("Src IP: %s \n", inet_ntoa(ip_src.sin_addr));

	ip_dst.sin_addr.s_addr = ip->daddr;
	printf("Dst IP: %s \n", inet_ntoa(ip_dst.sin_addr));

	struct icmphdr *icmp = (struct icmphdr *)(packet + (ip->ihl * 4) + 14);
	count ++;

	
}

int main()
{
	printf("Waiting for ICMP packet...\n\n");

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";
	bpf_u_int32 net;

	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	
	return 0;
}
