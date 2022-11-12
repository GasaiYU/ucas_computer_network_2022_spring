#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "rtable.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip_hdr -> daddr);

	// ICMP packet
	if (daddr == iface -> ip) {
		struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
		struct icmphdr *icmp_hdr = (struct icmphdr*)IP_DATA(ip_hdr);
		if (icmp_hdr -> type == ICMP_ECHOREQUEST) {
			icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
		} else {
			free(packet);
		}
		return;
	}

	// Search daddr in router table.
	rt_entry_t *p_rt = longest_prefix_match(daddr);
	if (p_rt == NULL) {
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		return;
	}

	// ttl
	ip_hdr -> ttl--;
	if (ip_hdr -> ttl <= 0) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		return;
	}
	ip_hdr -> checksum = ip_checksum(ip_hdr);
	
	// Get the next jump.
	u32 next_jump = p_rt -> gw? p_rt -> gw : daddr;

	// forward packet by arp protocol.
	iface_send_packet_by_arp(p_rt -> iface, next_jump, packet, len);
}	
