
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void spoof_reply(const u_char *packet, struct iphdr* ip,struct icmphdr* icmp);
unsigned short in_cksum(unsigned short *buf, int length);
void send_raw_ip_packet(struct iphdr* ip);







int main() {

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
	return 0 ;
}

void spoof_reply(const u_char *packet, struct iphdr* ip,struct icmphdr* icmp){

	char *data =(u_char *)packet + 14 + sizeof(struct iphdr) +sizeof(struct icmphdr );
	int size_data=ntohs(ip->tot_len) - (sizeof(struct iphdr) +sizeof(struct icmphdr ));
	icmp->type = 0;
	icmp->code=0;
        
	icmp -> checksum=0;
	icmp -> checksum= in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) +size_data);

	
	
	//10.0.2.15 >>> 1.2.3.4
	unsigned int temp =ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = temp;
	//1.2.3.4>>>>10.0.2.15
	

	
	send_raw_ip_packet (ip);
	
	
	
}
	
	
	
void send_raw_ip_packet(struct iphdr* ip){

	struct sockaddr_in dest_info;
	int enable =1;

	int sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock,IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	dest_info.sin_family = AF_INET;
	dest_info.sin_addr.s_addr = ip->daddr;

	printf("Sending spoofed IP packet ...\n");
	sendto(sock,ip,ntohs(ip->tot_len),0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	if(sendto(sock,ip,ntohs(ip->tot_len),0, (struct sockaddr *)&dest_info, sizeof(dest_info))<0)
	{ 
	perror("PACKET NOT SENT\n");
	return;
	}


	close(sock);
	
}



unsigned short in_cksum(unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length ;
	int sum=0;
	unsigned short temp =0;

	while(nleft>1){
	sum+= *w++;
	nleft -=2;
}

	if(nleft==1){
	*(u_char *)(temp) = *(u_char *)w;
	sum+= temp;
	}

	sum=(sum>> 16) +(sum & 0xffff);
	sum+= (sum>> 16) ;
	return (unsigned short)(~sum);

	}







int counter = 0;



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	struct sockaddr_in ip_src, ip_dst;
	struct iphdr *ip = (struct iphdr *)(packet + 14);
	struct icmphdr *icmp = (struct icmphdr *)(packet +14+ sizeof(struct iphdr));

	if(ip->saddr=inet_addr("10.0.2.15")){
	if(icmp->type == 8){
	printf("Got an ICMP packet!\n");
		printf("-----Request-----\n");
	

	ip_src.sin_addr.s_addr = ip->saddr;
	printf("Src IP: %s \n", inet_ntoa(ip_src.sin_addr));

	ip_dst.sin_addr.s_addr = ip->daddr;
	printf("Dst IP: %s \n", inet_ntoa(ip_dst.sin_addr));
	
	
	spoof_reply(packet, ip, icmp);
		}
	}
	

	counter++;
	
	
}


