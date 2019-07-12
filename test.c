#include <stdio.h>
#include<stdlib.h>
#include <pcap.h>
#include<time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<string.h>
#include"getinfo.h"
//回调函数
//void pcap_callback(unsigned char * arg,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content){
//    int *id=(int *)arg;//记录包ID
//    printf("id=%d\n",++(*id));
//
//    printf("Packet length : %d\n",packet_header->len);
//    printf("Number of bytes : %d\n",packet_header->caplen);
//    printf("Received time : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
//    int i;
//    for(i=0;i<packet_header->caplen;i++){
//        printf(" %02x",packet_content[i]);   //16进制码输出包的内容
//        if((i+1)%16==0){
//            printf("\n");
//        }
//    }
//    printf("\n\n");
//}

int main(int argc, char *argv[])
{
    char *dev,errbuf[1024];
    dev=pcap_lookupdev(errbuf); //获取网卡

    if(dev==NULL){
        printf("device is null\n");
        exit(1);
    }
    printf("网卡设备：%s\n",dev);

    pcap_t *pcap_handle=pcap_open_live(dev,65535,1,10,errbuf);  //打开网络设备，混杂模式 10ms

    if(pcap_handle==NULL){
        printf("%s\n",errbuf);
        exit(1);
    }

    struct in_addr addr;
    bpf_u_int32 ipaddress, ipmask;
    char *dev_ip,*dev_mask;

    if(pcap_lookupnet(dev,&ipaddress,&ipmask,errbuf)==-1){  //获取制定网络接口的ip，掩码
        printf("%s\n",errbuf);
        exit(1);
    }

    addr.s_addr=ipaddress;
    dev_ip=inet_ntoa(addr);
    printf("ip address : %s\n",dev_ip);  // 打印的地址是".0"的地址，不知道为什么

    addr.s_addr=ipmask;
    dev_mask=inet_ntoa(addr);
    printf("netmask : %s\n",dev_mask);

    printf("---------packet--------\n");
    int id=0;//传入回调函数记录ID

//    void ethernet_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt,const u_char *packet)

    if(pcap_loop(pcap_handle,-1,ethernet_callback,(unsigned char *)&id)<0){//接收十个数据包
        printf("error\n");
        return 0;
    }

    pcap_close(pcap_handle);

    return 0;
}
