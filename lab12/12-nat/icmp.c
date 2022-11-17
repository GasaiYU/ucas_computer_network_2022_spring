#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr *in_ip_hdr = packet_to_ip_hdr(in_pkt);

    int pkt_len = 0;
    if (type == ICMP_ECHOREPLY) {
        pkt_len = len;
    } else {
        pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE(in_ip_hdr) + 8;
	}
    
    char *sent_pkt = (char*)malloc(pkt_len);
    struct ether_header *eh = (struct ether_header*)sent_pkt;
    struct iphdr *ip_hdr = packet_to_ip_hdr(sent_pkt);
    struct icmphdr *icmp_hdr = (struct icmphdr*)(sent_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);

    eh -> ether_type = htons(ETH_P_IP);

    rt_entry_t *entry = longest_prefix_match(ntohl(in_ip_hdr -> saddr));
    ip_init_hdr(ip_hdr, entry -> iface -> ip, ntohl(in_ip_hdr -> saddr), pkt_len - ETHER_HDR_SIZE, 1);
    
    icmp_hdr -> code = code;
    icmp_hdr -> type = type;

    if (type == 0) {
        memcpy(sent_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(ip_hdr) + 4, \
        in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(in_ip_hdr) + 4, pkt_len - (ETHER_HDR_SIZE + IP_HDR_SIZE(in_ip_hdr) + 4));
    } else {
        memset(sent_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(ip_hdr) + 4, 0, 4);
		memcpy(sent_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(ip_hdr) + 4 + 4, \
        in_ip_hdr, IP_HDR_SIZE(in_ip_hdr) + 8);
    }

    icmp_hdr -> checksum = icmp_checksum(icmp_hdr, pkt_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE);
	ip_send_packet(sent_pkt, pkt_len);
}
