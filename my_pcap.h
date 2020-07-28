#pragma once
#include <time.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6
/* Ethernet header */
struct EthernetHeader {
    u_char DstMAC[ETHER_ADDR_LEN]; /* Destination host address */
    u_char SrcMAC[ETHER_ADDR_LEN]; /* Source host address */
    u_short type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct IPHeader {
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f) // header len (*4, 20-60)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4) //version

    uint8_t ip_vhl;		/* version (4)| header length(4) */
    uint8_t ip_tos;		/* type of service (DSCP:CSO, ENC:Not-ECT)*/
    uint16_t ip_len;		/* total length */
    uint16_t ip_id;		/* identification */
    uint16_t ip_offset;		/* fragment offset field */
    uint8_t ip_ttl;		/* time to live */
    uint8_t ip_protocol;		/* protocol */
    uint16_t ip_checksum;		/* checksum */
   struct in_addr SrcAddr,DstAddr; /* source and dest address (32 bit, 32bit)*/
};

/* TCP header */
typedef u_int tcp_seq;
//TCP flag
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
struct TCPHeader {
    uint16_t src_port;	/* source port */
    uint16_t dst_port;	/* destination port */
    uint32_t seq_num;		/* sequence number */
    uint32_t ack_num;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd tcp size*4(20-60)*/
    uint8_t th_flags;
    uint16_t win_size;		/* window */
    uint16_t checksum;		/* checksum */
    uint16_t th_urp;		/* urgent pointer */
};

void usage();
void print_packet_info(const u_char* packet);
