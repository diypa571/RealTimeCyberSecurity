#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/*
Diyar Parwana
Real Time Monitoring (Realtidsövervakning)
How to run it?
1- Usin linux, get the network interface with the command ifconfig
2- Compile it using the g++
g++ -o main nids.cpp -lpcap
3- sudo ./main network-inerface


Den här koden är ett enkelt program skrivet i C som fungerar som en nätverksövervakare, realtidsövervakning. 
Koden använder PCAP-biblioteket för att fånga nätverkspaket från en angiven nätverksgränssnitt (network interface)
och skriver ut information om käll-IP-adressen för varje mottaget paket.

Inkluderar nödvändiga huvudfiler, inklusive <stdio.h>, <stdlib.h>, <pcap.h>, <netinet/ip.h>, och <arpa/inet.h>.

Definierar en funktion packet_handler som kommer att anropas för varje fångat paket. Inuti denna funktion:

Extraheras och lagras käll-IP-adressen från paketet.
Kollar om käll-IP-adressen är lokal (om den börjar med "192.") eller inte.
Om käll-IP-adressen inte är lokal, skriver programmet ut käll-IP-adressen och längden på det fångade paketet.
I main-funktionen:
 

*/

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14);

    // Get the source IP address
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

    // Check if the source IP address is local (starts with "192.") or not
    if (src_ip[0] != '1' || src_ip[1] != '9' || src_ip[2] != '2') {
        // Print the source IP address only if it's not local
        printf("Source IP: %s\n", src_ip);
        printf("Packet received. Length: %d\n", pkthdr->len);
    }
}

int main(int argc, char *argv[]) {
    char *dev; // Specify the network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Check for network interface argument
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    dev = argv[1];

    // Capture network interface packets
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Sniffing: %s\n", dev);

    // Fånga packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the capture session when done
    pcap_close(handle);

    return 0;
}
