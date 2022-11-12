#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	char *packet = (char*)malloc(sizeof(struct ether_arp) + ETHER_HDR_SIZE);
	
	struct ether_header *eh = (struct ether_header*)packet;
	struct ether_arp *ea = (struct ether_arp*)(packet + ETHER_HDR_SIZE);

	memset(eh -> ether_dhost, 0xff, ETH_ALEN);
	memcpy(eh -> ether_shost, iface -> mac, ETH_ALEN);
	eh -> ether_type = htons(ETH_P_ARP);

	ea -> arp_hrd = htons(ARPHRD_ETHER);
	ea -> arp_pro = htons(ETH_P_IP);
	ea -> arp_hln = ETH_ALEN;
	ea -> arp_pln = 4;
	ea -> arp_op = htons(ARPOP_REQUEST);
	memcpy(ea -> arp_sha, iface -> mac, ETH_ALEN);
	ea -> arp_spa = htonl(iface -> ip);
	memset(ea -> arp_tha, 0, ETH_ALEN);
	ea -> arp_tpa = htonl(dst_ip);

	iface_send_packet(iface, packet, sizeof(struct ether_arp) + ETHER_HDR_SIZE);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	char *packet = (char*)malloc(sizeof(struct ether_arp) + ETHER_HDR_SIZE);
	
	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *ea = (struct ether_arp*)(packet + ETHER_HDR_SIZE);

	memcpy(eh -> ether_dhost, req_hdr -> arp_sha, ETH_ALEN);
	memcpy(eh -> ether_shost, iface -> mac, ETH_ALEN);
	eh -> ether_type = htons(ETH_P_ARP);

	ea -> arp_hrd = htons(ARPHRD_ETHER);
	ea -> arp_pro = htons(ETH_P_IP);
	ea -> arp_hln = ETH_ALEN;
	ea -> arp_pln = 4;
	ea -> arp_op = htons(ARPOP_REPLY);
	memcpy(ea -> arp_sha, iface -> mac, ETH_ALEN);
	ea -> arp_spa = htonl(iface -> ip);
	memcpy(ea -> arp_tha, req_hdr -> arp_sha, ETH_ALEN);
	ea -> arp_tpa = req_hdr -> arp_spa;

	iface_send_packet(iface, packet, sizeof(struct ether_arp) + ETHER_HDR_SIZE);
}

// Judge if the packet is send/recv packet and take some measures.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *ea = (struct ether_arp*)(packet + ETHER_HDR_SIZE);
	if (ntohl(ea -> arp_tpa) == iface -> ip) {
		if (ntohs(ea -> arp_op) == ARPOP_REPLY) {
			arpcache_insert(ntohl(ea -> arp_spa), ea -> arp_sha);
		} else if (ntohs(ea -> arp_op) == ARPOP_REQUEST) {
			arp_send_reply(iface, ea);
		}
	}

}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
