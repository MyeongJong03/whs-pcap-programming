#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#include "myheader.h"

#define SIZE_ETHERNET 14
#define ETHER_TYPE_IP 0x0800

static void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_readable_payload(const u_char *payload, int payload_len)
{
    int i;

    for (i = 0; i < payload_len; i++) {
        unsigned char ch = payload[i];

        if (isprint(ch) || ch == '\r' || ch == '\n' || ch == '\t') {
            putchar(ch);
        } else {
            putchar('.');
        }
    }

    if (payload_len > 0 && payload[payload_len - 1] != '\n') {
        putchar('\n');
    }
}

static char *find_default_interface(char *errbuf)
{
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    pcap_if_t *selected = NULL;
    char *interface_name;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return NULL;
    }

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        if ((dev->flags & PCAP_IF_LOOPBACK) == 0 &&
            strcmp(dev->name, "any") != 0) {
            selected = dev;
            break;
        }
    }

    if (selected == NULL) {
        selected = alldevs;
    }

    interface_name = selected != NULL ? strdup(selected->name) : NULL;
    pcap_freealldevs(alldevs);

    return interface_name;
}

static void got_packet(u_char *args, const struct pcap_pkthdr *header,
                       const u_char *packet)
{
    const struct ethheader *eth;
    const struct ipheader *ip;
    const struct tcpheader *tcp;
    const u_char *payload;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    bpf_u_int32 caplen = header->caplen;
    unsigned int ip_total_len;
    unsigned int ip_header_len;
    unsigned int tcp_header_len;
    unsigned int transport_offset;
    int payload_len;

    (void)args;

    if (caplen < SIZE_ETHERNET) {
        return;
    }

    eth = (const struct ethheader *)packet;
    if (ntohs(eth->ether_type) != ETHER_TYPE_IP) {
        return;
    }

    if (caplen < SIZE_ETHERNET + sizeof(struct ipheader)) {
        return;
    }

    ip = (const struct ipheader *)(packet + SIZE_ETHERNET);
    ip_header_len = ip->iph_ihl * 4;
    if (ip->iph_ver != 4 || ip_header_len < sizeof(struct ipheader)) {
        return;
    }

    if (caplen < SIZE_ETHERNET + ip_header_len) {
        return;
    }

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    transport_offset = SIZE_ETHERNET + ip_header_len;
    if (caplen < transport_offset + sizeof(struct tcpheader)) {
        return;
    }

    tcp = (const struct tcpheader *)(packet + transport_offset);
    tcp_header_len = TH_OFF(tcp) * 4;
    if (tcp_header_len < sizeof(struct tcpheader)) {
        return;
    }

    if (caplen < transport_offset + tcp_header_len) {
        return;
    }

    ip_total_len = ntohs(ip->iph_len);
    if (ip_total_len < ip_header_len + tcp_header_len) {
        return;
    }

    payload_len = (int)(ip_total_len - ip_header_len - tcp_header_len);
    if ((unsigned int)payload_len > caplen - transport_offset - tcp_header_len) {
        payload_len = (int)(caplen - transport_offset - tcp_header_len);
    }

    payload = packet + transport_offset + tcp_header_len;

    if (inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, sizeof(src_ip)) == NULL) {
        strncpy(src_ip, "unknown", sizeof(src_ip));
        src_ip[sizeof(src_ip) - 1] = '\0';
    }

    if (inet_ntop(AF_INET, &(ip->iph_destip), dst_ip, sizeof(dst_ip)) == NULL) {
        strncpy(dst_ip, "unknown", sizeof(dst_ip));
        dst_ip[sizeof(dst_ip) - 1] = '\0';
    }

    printf("========================================\n");
    printf("[Ethernet Header]\n");
    printf("Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n\n");

    printf("[IP Header]\n");
    printf("Src IP  : %s\n", src_ip);
    printf("Dst IP  : %s\n\n", dst_ip);

    printf("[TCP Header]\n");
    printf("Src Port: %u\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %u\n\n", ntohs(tcp->tcp_dport));

    printf("[HTTP Message]\n");
    if (payload_len <= 0) {
        printf("No HTTP payload or empty TCP payload.\n");
    } else {
        print_readable_payload(payload, payload_len);
    }
    printf("========================================\n\n");
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    const char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;
    char *selected_interface = NULL;
    const char *interface_name;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        interface_name = argv[1];
    } else {
        selected_interface = find_default_interface(errbuf);
        if (selected_interface == NULL) {
            fprintf(stderr, "Could not find a network interface: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        interface_name = selected_interface;
    }

    if (pcap_lookupnet(interface_name, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = PCAP_NETMASK_UNKNOWN;
    }

    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open interface %s: %s\n", interface_name, errbuf);
        free(selected_interface);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface %s does not use Ethernet link-layer headers.\n",
                interface_name);
        pcap_close(handle);
        free(selected_interface);
        return EXIT_FAILURE;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
        fprintf(stderr, "Could not compile BPF filter '%s': %s\n",
                filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        free(selected_interface);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not set BPF filter '%s': %s\n",
                filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        free(selected_interface);
        return EXIT_FAILURE;
    }

    printf("Listening on interface: %s\n", interface_name);
    printf("BPF filter: %s\n\n", filter_exp);

    if (pcap_loop(handle, -1, got_packet, NULL) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        free(selected_interface);
        return EXIT_FAILURE;
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    free(selected_interface);

    return EXIT_SUCCESS;
}
