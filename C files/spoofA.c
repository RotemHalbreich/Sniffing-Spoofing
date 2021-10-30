#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#define SRC_IP "1.2.3.4"
#define DST_IP "10.0.2.15"


unsigned short in_cksum(unsigned short *buf, int length);
void send_raw_ip_packet(struct iphdr* ip);



int main() {
char buffer[1028];
memset(buffer, 0, 1028);

struct icmp *icmp = (struct icmp *)(buffer + sizeof(struct iphdr)); //creating the icmp packet to be 0(reply)
icmp->icmp_type = 0;//reply type
icmp->icmp_code =0;
//icmp->icmp_seq;

icmp ->icmp_cksum=0;
icmp ->icmp_cksum= in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));

struct sockaddr_in ip_src, ip_dst;
struct iphdr *ip = (struct iphdr *)buffer; //creating the spoofed packet to be "1.2.3.4" and to be sent straight to the user
ip->version=4;
ip->ihl=5;
ip->tos=16;
ip->id=htons(54321);
ip->ttl=64;
ip->saddr = inet_addr(SRC_IP);
ip->daddr = inet_addr(DST_IP);
ip->protocol = IPPROTO_ICMP;
ip->tot_len= htons(100);

send_raw_ip_packet (ip);

}
void send_raw_ip_packet(struct iphdr* ip){//creating the raw socket and sending the spoofed packet

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























