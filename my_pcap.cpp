#include "my_pcap.h"
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0(eth0)\n");
}

void MAC_print(const char* msg, unsigned char* mac) {
    printf("%s%02X:%02X:%02X:%02X:%02X:%02X\n", msg, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ;
}
void print_packet_info(const u_char* packet){
    EthernetHeader *ethernet; /* The ethernet header */
    IPHeader *ip; /* The IPv4 header */
    TCPHeader *tcp_header; /* The TCP header */
    uint16_t payload_len = 0; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct EthernetHeader*)(packet);
    MAC_print("Dst MAC : ", ethernet->SrcMAC);
    MAC_print("Src MAC : ", ethernet->DstMAC);
    if(ethernet->type == 0x0800) printf("Type : %x", ethernet->type);
    packet += sizeof(EthernetHeader);

    ip = (struct IPHeader*)(packet);
    printf("  Dst IP Header : %s", inet_ntoa(ip->DstAddr)); //bit -> string
    printf("\n  Src IP Header : %s ", inet_ntoa(ip->SrcAddr));
    size_ip = IP_HL(ip)*4;//header len(&0x0f)*4 (20-60)
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return ;
     }
     packet +=size_ip;

     tcp_header = (struct TCPHeader*)(packet);
     printf("\n     Dst TCP Port: %d", ntohs(tcp_header->dst_port));
     printf("\n     Src TCP Port: %d", ntohs(tcp_header->src_port));
     size_tcp = TH_OFF(tcp_header)*4;// (data offset & 0xf0) >>4
     if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return ;
     }
     packet += size_tcp;

     payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
     if(payload_len == 0) printf("\n not payload\n");
     else{
        printf("\n      Payload : \n");
        for(int i =0; i<payload_len; i++) {
            printf("%02x ", packet[i]);
            if(i % 8 == 7) { printf ("   ");}
            if(i % 16 == 15) {printf("\n");}
        }
     }
     printf("\n=============================================================\n");
}
