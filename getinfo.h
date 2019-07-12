#ifndef _GETINFO_H_
#define _GETINFO_H_


#include<stdio.h>
#include<time.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<string.h>
#include<pcap.h>
#include"head.h"

void ethernet_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet);
void pppoe_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet);
char *tcp_flag(const u_char tcp_flags);
void ip_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet);
void tcp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet);
void icmp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet);
void udp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet);
void arp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet);


/*****************************************************************************
 函 数 名  : ethernet_callback
 功能描述  : 以太网数据包头分析
*****************************************************************************/
void ethernet_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)
{
	struct ethernet *ethheader;
	struct ip *ipptr;
	u_short protocol;
	u_int *id = (u_int *)arg;
	u_char *time = ctime((const time_t*)&pcap_pkt->ts.tv_sec);

	printf("-----------------Analyze Info---------------\n");
	printf("Id: %d\n",++(*id));
	printf("Packet length: %d\n",pcap_pkt->len);
	printf("Number of bytes: %d\n",pcap_pkt->caplen);
	printf("Receive time: %s\n",time);

	int k;
	for (k = 0; k < pcap_pkt->len; k++)
	{
		/*表示以16进制的格式输出整数类型的数值，
		输出域宽为2，右对齐，不足的用字符0替代*/
		printf(" %02x",packet[k]);
		if ((k + 1) % 16 == 0)
		{
			printf("\n");
		}
	}

	printf("\n\n");

	ethheader = (struct ethernet*)packet;
	printf("---------------Data Link Layer-----------\n");

	printf("Mac Src Address: ");
	int i;
	for (i = 0; i < ETHERNET_ADDR_LEN; i++)
	{
		if (ETHERNET_ADDR_LEN - 1 == i)
		{
			printf("%02x\n",ethheader->ether_shost[i]);
		}
		else
		{
		printf("%02x:",ethheader->ether_shost[i]);
		}
	}

	printf("Mac Dst Address: ");
	int j;
	for (j = 0; j < ETHERNET_ADDR_LEN; j++)
	{
		if (ETHERNET_ADDR_LEN - 1 == j)
		{
			printf("%02x\n",ethheader->ether_dhost[j]);
		}
		else
		{
		printf("%02x:",ethheader->ether_dhost[j]);
		}
	}

	protocol = ntohs(ethheader->ether_type);

    /*对pppoe报文的处理*/
    if (0x8863 == protocol)
    {
        printf("PPPOE Discovery");
        pppoe_callback(arg, pcap_pkt, packet);
    }
    if (0x8864 == protocol)
    {
        printf("PPPOE Session");
        pppoe_callback(arg, pcap_pkt, packet);
    }

	printf("----------------Network Layer-------------\n");
	switch (protocol)
	{
		case 0x0800:
			printf("IPv4 protocol!\n");
			ip_callback(arg, pcap_pkt, packet);
			break;
		case 0x0806:
			printf("ARP protocol!\n");
			arp_callback(arg, pcap_pkt, packet);
			break;
		case 0x8035:
			printf("RARP protocol!\n");
			break;
		case 0x86DD:
			printf("IPv6 protocol!\n");
			break;
		case 0x880B:
			printf("PPP protocol!\n");
			printf("There is no function to process PPP packet!!!");
			break;
		default:
			printf("Other Network Layer protocol is used!\n");
			break;
	}
	printf("---------------------Done--------------------\n\n\n");
}

/*****************************************************************************
 函 数 名  : pppoe_callback
 功能描述  : pppoe数据包处理函数
*****************************************************************************/
void pppoe_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)
{
    struct pppoe *pppoeheader = (struct pppoe *)(packet + ETHERNET_HEAD_SIZE);
    printf("Version: %d\n",(pppoeheader->pppoe_vtype & 0xf0) >> 4);
    printf("Type: %d\n",pppoeheader->pppoe_vtype & 0x0f);
    printf("Code: %d\n",pppoeheader->pppoe_code);
    printf("Session ID: %d\n",ntohs(pppoeheader->pppoe_s_id));
    printf("Payload Length: %d\n",ntohs(pppoeheader->pppoe_len));
}

/*****************************************************************************
 函 数 名  : ip_callback
 功能描述  : ip数据包分析
*****************************************************************************/
void ip_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)
{
	u_char protocol;
	struct ip *ipheader;
	ipheader = (struct ip *)(packet + ETHERNET_HEAD_SIZE);

	printf("Version: %d\n", (ipheader->ip_hlv & 0xf0) >> 4); //取hlv高4位
	printf("Header Length: %d\n",ipheader->ip_hlv & 0x0f);  //取hlv低4位
	printf("Type of Service: %x\n",ipheader->ip_tos);
	printf("Total Length: %d\n",ntohs(ipheader->ip_len));
	printf("Indentification: %x\n",ntohs(ipheader->ip_id));
	printf("Offset: %d\n",ntohs(ipheader->ip_off));
	printf("TTL: %d\n",ipheader->ip_ttl);
	printf("Protocol: %d\n",ipheader->ip_protocol);
	printf("CheckSum: %d\n",ntohs(ipheader->ip_sum));
	int i = 0;
	printf("IP Src Address: ");
	for (i = 0; i < IP_ADDR_LEN; i++)
	{
		printf("%d.",ipheader->ip_src[i]);
	}
	printf("\nIP Dst Address: ");
	for (i = 0; i < IP_ADDR_LEN; i++)
	{
		printf("%d.",ipheader->ip_dst[i]);
	}
	printf("\n");

    protocol = ipheader->ip_protocol;
    if (0x01 == protocol)
    {
        printf("ICMP Protocol!\n");
		icmp_callback(arg, pcap_pkt, packet);
    }

	printf("----------------Transport Layer--------------\n");
	switch (protocol)
	{
		case 0x06:
			printf("TCP Protocol!\n");
			tcp_callback(arg, pcap_pkt, packet);
			break;
		case 0x11:
			printf("UDP Protocol!\n");
			udp_callback(arg, pcap_pkt, packet);
			break;
		case 0x02:
			printf("IGMP Protocol!\n");
			printf("There is no function to process IGMP packet!!!");
			break;
		default:
			printf("Other Transport Layer protocol is used!\n");
			break;
	}
}

/*****************************************************************************
 函 数 名  : tcp_callback
 功能描述  : TCP数据包分析
*****************************************************************************/
void tcp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)
{
	struct tcp *tcpheader = (struct tcp *)(packet + ETHERNET_HEAD_SIZE + IP_HEAD_SIZE(packet));

	printf("Src Port: %d\n",ntohs(tcpheader->tcp_sport));
	printf("Dst Port: %d\n",ntohs(tcpheader->tcp_dport));
	printf("Squence Number: %d\n",ntohs(tcpheader->tcp_seqe));
	printf("ACK Number: %d\n",ntohs(tcpheader->tcp_ack));
	printf("Header Length: %d\n",(tcpheader->tcp_hre & 0xf0) >> 4);
	printf("FLAG: %d\n",tcpheader->tcp_flag);
	printf("Flag: %s\n",tcp_flag(tcpheader->tcp_flag));
	printf("Window Size: %d\n",ntohs(tcpheader->tcp_win));
	printf("Checksum: %d\n",ntohs(tcpheader->tcp_sum));
	printf("Urgent Pointer: %d\n",ntohs(tcpheader->tcp_urp));
}


/*****************************************************************************
 函 数 名  : tcpflag
 功能描述  : 判断TCP协议的标志位
*****************************************************************************/
char *tcp_flag(const u_char tcp_flags)
{
	char flags[100] = "-";
	if ((TCP_CWR & tcp_flags) == TCP_CWR)
	{
		strncat(flags, "CWR ", 100);
	}
	if ((TCP_ECE & tcp_flags) == TCP_ECE)
	{
		strncat(flags, "ECE ", 100);
	}
	if ((TCP_URG & tcp_flags) == TCP_URG)
	{
		strncat(flags, "URG ", 100);
	}
	if ((TCP_ACK & tcp_flags) == TCP_ACK)
	{
		strncat(flags, "ACK ", 100);
	}
	if ((TCP_PUSH & tcp_flags) == TCP_PUSH)
	{
		strncat(flags, "PUSH ", 100);
	}
	if ((TCP_RST & tcp_flags) == TCP_RST)
	{
		strncat(flags, "RST ", 100);
	}
	if ((TCP_SYN & tcp_flags) == TCP_SYN)
	{
		strncat(flags, "SYN ", 100);
	}
	if ((TCP_FIN & tcp_flags) == TCP_FIN)
	{
		strncat(flags, "FIN ", 100);
	}
	return flags;
}


/*****************************************************************************
 函 数 名  : icmp_callback
 功能描述  : ICMP数据包分析
*****************************************************************************/
void icmp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)
{
    struct icmp *icmpheader = (struct icmp *)(packet + ETHERNET_HEAD_SIZE + IP_HEAD_SIZE(packet));
    u_char icmp_type = icmpheader->icmp_type;

    printf("ICMP Type: %d   ",icmpheader->icmp_type);
    switch (icmp_type)
    {
        case 0x08:
            printf("(ICMP Request)\n");
            break;
        case 0x00:
            printf("(ICMP Response)\n");
            break;
        case 0x11:
            printf("(Timeout!!!)\n");
            break;
    }

    printf("ICMP Code: %d\n",icmpheader->icmp_code);
    printf("ICMP CheckSum: %d\n",icmpheader->icmp_sum);
}


/*****************************************************************************
 函 数 名  : udp_callback
 功能描述  : UDP数据包分析
*****************************************************************************/
void udp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)
{
    struct udp *udpheader = (struct udp *)(packet + ETHERNET_HEAD_SIZE + IP_HEAD_SIZE(packet));

    printf("Src Port: %d\n",ntohs(udpheader->udp_sport));
    printf("Dst Port: %d\n",ntohs(udpheader->udp_dport));
    printf("UDP Length: %d\n",ntohs(udpheader->udp_len));
    printf("Checksum: %d\n",ntohs(udpheader->udp_sum));
}


/*****************************************************************************
 函 数 名  : arp_callback
 功能描述  : arp数据包分析
*****************************************************************************/
void arp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)
{
	struct arp *arpheader;

	arpheader = (struct arp *)(packet + ETHERNET_HEAD_SIZE);
	printf("Hardware type: %s\n",(ntohs(arpheader->arp_hrd) == 0x0001) ? "Ethernet" : "Unknow");
	printf("Protocol type: %s\n",(ntohs(arpheader->arp_pro) == 0x0800) ? "IPv4" : "Unknow");
	printf("Operation: %s\n",(ntohs(arpheader->arp_op) == ARP_REQUEST) ? "ARP_Request" : "ARP_Reply");
	int i = 0;
	printf("Sender MAC:");
	for (i = 0; i < ETHERNET_ADDR_LEN; i++)
	{
		printf("%02x:",arpheader->arp_shost[i]);
	}
	printf("\nSender IP:");
	for (i = 0; i < IP_ADDR_LEN; i++)
	{
		printf("%d.",arpheader->arp_sip[i]);
	}
	printf("\nTarget Mac:");
	for (i = 0; i < ETHERNET_ADDR_LEN; i++)
	{
		printf("%02x:",arpheader->arp_dhost[i]);
	}
	printf("\nTarget IP:");
	for (i = 0; i < IP_ADDR_LEN; i++)
	{
		printf("%d.",arpheader->arp_dip[i]);
	}
	printf("\n\n");
}
#endif
