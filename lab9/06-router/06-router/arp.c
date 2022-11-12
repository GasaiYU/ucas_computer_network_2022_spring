#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "ip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	//fprintf(stdout,"request ip:"IP_FMT"\n", HOST_IP_FMT_STR(dst_ip));
	char *arp_packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eh= (struct ether_header *)arp_packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	memset(eh->ether_dhost, 0xFF, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);
	struct ether_arp *arp = (struct ether_arp *)(arp_packet + ETHER_HDR_SIZE);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = 6;
	arp->arp_pln = 4;
	arp->arp_op  = htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	memset(arp->arp_tha, 0, ETH_ALEN);
	arp->arp_tpa = htonl(dst_ip);
	iface_send_packet(iface, arp_packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//fprintf(stdout,"reply\n");
	char *arp_packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eh= (struct ether_header *)arp_packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);
	struct ether_arp *arp = (struct ether_arp *)(arp_packet + ETHER_HDR_SIZE);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = 6;
	arp->arp_pln = 4;
	arp->arp_op  = htons(ARPOP_REPLY);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	//fprintf(stdout, "reply arp ip:"IP_FMT" mac: %d""\n", HOST_IP_FMT_STR(iface->ip), (iface->mac));
	memcpy(arp->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	arp->arp_tpa = req_hdr->arp_spa;
	iface_send_packet(iface, arp_packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	if(ntohl(arp->arp_tpa) == iface->ip){
		if(ntohs(arp->arp_op) == ARPOP_REQUEST){
			//fprintf(stdout, "recv arp request\n");
			arp_send_reply(iface, arp);
		}else if (ntohs(arp->arp_op) == ARPOP_REPLY){
			//fprintf(stdout, "insert arp ip:"IP_FMT" mac: %d""\n", HOST_IP_FMT_STR(arp->arp_spa),(arp->arp_sha));
			arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
		}
	}else{
		free(packet);
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
		//log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		//log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
