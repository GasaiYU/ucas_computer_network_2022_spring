#include "ip.h"
#include <rtable.h>
#include <stdio.h>
#include <stdlib.h>
#include <icmp.h>
#include <ether.h>
#include <string.h>
#include <arp.h>
// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stdout, "handle IP pkt\n");
	struct iphdr * ip_header = packet_to_ip_hdr(packet);
	u32 dest = ntohl(ip_header->daddr); 
	//fprintf(stdout, "dest:"IP_FMT"\t iface:"IP_FMT"\n", HOST_IP_FMT_STR(dest),HOST_IP_FMT_STR(iface->ip));
	if(dest == iface->ip){
		u8 type = (u8)*(packet + ETHER_HDR_SIZE + IP_HDR_SIZE(ip_header));
		//fprintf(stdout, "type:%d\n", type);
		if(type == ICMP_ECHOREQUEST){
			//fprintf(stdout, "ping\n");
			icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
		}else{
			free(packet);
		}	
	}else{
		//fprintf(stdout,"router\n");
		//fprintf(stdout, "input_dest:"IP_FMT"\n",HOST_IP_FMT_STR(dest));
		rt_entry_t *router = longest_prefix_match(dest);
		//fprintf(stdout, "router.dest:"IP_FMT"\t router.gw "IP_FMT"\n", HOST_IP_FMT_STR(router->dest),HOST_IP_FMT_STR(router->gw));
		if(router){
			ip_header->ttl--;
			if(ip_header->ttl <= 0){
				icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
				return;
			}
			ip_header->checksum = ip_checksum(ip_header);
			if(router->gw){
				//fprintf(stdout,"zhuanfa\n");
				iface_send_packet_by_arp(router->iface, router->gw, packet, len);
			}else{
				iface_send_packet_by_arp(router->iface, dest, packet, len);
			}
		}else{
			icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		}
	}
}
