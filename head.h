#ifndef _HEAD_H_
#define _HEAD_H_

#include<sys/types.h>
#include<netinet/in.h>

/*最大抓包长度 ：Ethernet 1500字节 + 以太网帧头部14字节 + 以太网帧尾部4字节*/
#define SNAP_LEN 1518

/*ethernet head are exactly 14 bytes*/
#define ETHERNET_HEAD_SIZE 14

/*ip头部字节数宏  取hlv低四位即头部长度*单位4bytes  然后强转为ip结构体*/
//#define IP_HEAD_SIZE(ipheader) ((ipheader->ip_hlv & 0x0f) * 4)
#define IP_HEAD_SIZE(packet)  ((((struct ip *)(packet + ETHERNET_HEAD_SIZE))->ip_hlv & 0x0f) * 4)

/*ethernet address are 6 bytes*/
#define ETHERNET_ADDR_LEN 6

/*ip address are 4 bytes*/
#define IP_ADDR_LEN 4

#define ARP_REQUEST 1
#define ARP_REPLY 2

/*TCP flag*/
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

/*Ethernet HEADER*/
struct ethernet
{
	u_char ether_dhost[ETHERNET_ADDR_LEN];
	u_char ether_shost[ETHERNET_ADDR_LEN];
	u_short ether_type;  //IP?ARP?etc
};

/*IP HEADER*/
struct ip
{
	//unsigned int ip_version:4;
	//unsigned int ip_hlen:4;
	u_char ip_hlv; /*version + headlength 如果分开定义会有大小端问题，会增加额外的判断*/
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	u_char ip_ttl;
	u_char ip_protocol;
	u_short ip_sum;
	u_char ip_src[IP_ADDR_LEN];
	u_char ip_dst[IP_ADDR_LEN];
};

/*TCP HEADER*/
struct tcp
{
	u_short tcp_sport;
	u_short tcp_dport;
	u_int tcp_seqe;
	u_int tcp_ack;

	//u_char tcp_off:4;
	//u_char tcp_unused:4;  //保留位
	u_char tcp_hre;  //header(4bits) + reserved(4bits)
	u_char tcp_flag;
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
};

/*UDP HEADER*/
struct udp
{
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_len;
	u_short udp_sum;
};

/*ARP HEADER 8+6+4+6+4*/
struct arp
{
	u_short arp_hrd; //hardware
	u_short arp_pro;  //protocol
	u_char arp_hdlen; //hardware address length
	u_char arp_prolen; //protocol length
	u_short arp_op;  //arp operations
	u_char arp_shost[ETHERNET_ADDR_LEN];
	u_char arp_sip[IP_ADDR_LEN];
	u_char arp_dhost[ETHERNET_ADDR_LEN];
	u_char arp_dip[IP_ADDR_LEN];
};

/*ICMP HEADER*/
struct icmp
{
	u_char icmp_type;
	u_char icmp_code;
	u_short icmp_sum;
	u_short icmp_id;
	u_short icmp_seq;
	u_int icmp_time;
};

/*PPPOE HEADER*/
struct pppoe
{
    u_char pppoe_vtype;  //version(0x1) + type(0x1)
    u_char pppoe_code;
    u_short pppoe_s_id;
    u_short pppoe_len;
};
#endif
