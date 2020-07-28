#include "my_pcap.h"
#include <stdio.h>


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    //packet sniff session create, maxsize : BUFSIZ, 1ms
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    int packetNumber =1;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); // success : 1, timeout: 0, error:-1
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("Packet No. %d \n", packetNumber++);
        printf("%u bytes captured\n", header->caplen);
        print_packet_info(packet);
    }

    pcap_close(handle);
}
