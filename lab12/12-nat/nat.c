#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	// fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *ih = packet_to_ip_hdr(packet);
	rt_entry_t *match = longest_prefix_match(ntohl(ih->saddr));

	if (match->iface->index == nat.internal_iface->index) {
		return DIR_OUT;
	} else if (match->iface->index == nat.external_iface->index) {
		return DIR_IN;
	}

	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// fprintf(stdout, "TODO: do translation for this packet.\n");
	pthread_mutex_lock(&nat.lock);
	struct iphdr *ih = packet_to_ip_hdr(packet);
	struct tcphdr *th = packet_to_tcp_hdr(packet);

	// Get hash addr.
	u32 addr = (dir == DIR_IN)? ntohl(ih->saddr) : ntohl(ih->daddr);
	u16 port = (dir == DIR_IN)? ntohs(th->sport) : ntohs(th->dport);
	rmt_set_t rs;
	rs.ip = addr;
	rs.port = port;
	u8 hash = hash8((char*)&rs, sizeof(rmt_set_t));
	if (dir == DIR_IN) {
		int found = 0;
		struct list_head *head = &(nat.nat_mapping_list[hash]);
		struct nat_mapping *map;
		struct nat_mapping *new_mapping = (struct nat_mapping*)malloc(sizeof(struct nat_mapping));

		list_for_each_entry(map, head, list) {
			if (map->external_ip == ntohl(ih->daddr) && map -> external_port == ntohs(th->dport)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			struct dnat_rule *rule;
			list_for_each_entry(rule, &nat.rules, list) {
				if (nat.assigned_ports[rule->external_port] == 0 && rule->external_ip == ntohl(ih->daddr) \
					&& rule->external_port == ntohs(th->dport)) {
						nat.assigned_ports[rule->external_port] = 1;
						new_mapping->external_ip = rule->external_ip;
						new_mapping->external_port = rule->external_port;
						new_mapping->internal_ip = rule->internal_ip;
						new_mapping->internal_port = rule->internal_port;
						list_add_tail(&(new_mapping->list), head);
						map = new_mapping;
						break;
				}
			}
		}

		th->dport = htons(map->internal_port);
		ih->daddr = htonl(map->internal_ip);

		map->conn.external_seq_end = th->seq;
		if (th->flags == TCP_ACK) {
			map->conn.external_ack = th->ack;
		}
		map->conn.external_fin = (th->flags == TCP_FIN)? TCP_FIN : 0;
		map->update_time = time(NULL);
	} else if (dir == DIR_OUT) {
		int found = 0;
		struct list_head *head = &(nat.nat_mapping_list[hash]);
		struct nat_mapping *map;
		struct nat_mapping *new_mapping = (struct nat_mapping*)malloc(sizeof(struct nat_mapping));

		list_for_each_entry(map, head, list) {
			if (map->internal_ip == ntohl(ih->saddr) && map->internal_port == ntohs(th->sport)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			int i;
			for (i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++) {
				if (nat.assigned_ports[i] == 0) {
					nat.assigned_ports[i] = 1;
					break;
				}
			}
			
			if (i == NAT_PORT_MAX) {
				perror("No available port!\n");
			}

			new_mapping->external_ip = nat.external_iface->ip;
			new_mapping->external_port = i;
			new_mapping->internal_ip = ntohl(ih->saddr);
			new_mapping->internal_port = ntohs(th->sport);
			
			list_add_tail(&(new_mapping->list), head);
			map = new_mapping;

		}

		ih->saddr = htonl(map->external_ip);
		th->sport = htons(map->external_port);

		map->conn.external_seq_end = th->seq;
		if (th->flags == TCP_ACK) {
			map->conn.external_ack = th->ack;
		}
		map->conn.external_fin = (th->flags == TCP_FIN)? TCP_FIN : 0;

		map->update_time = time(NULL);
	}
	
	ih->checksum = ip_checksum(ih);
	th->checksum = tcp_checksum(ih, th);

	pthread_mutex_unlock(&nat.lock);
	
	ip_send_packet(packet, len);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1) {
		// fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		pthread_mutex_lock(&nat.lock);
		time_t now = time(NULL);
		for (int i = 0; i < HASH_8BITS; i++) {
			struct list_head *head = &(nat.nat_mapping_list[i]);
			if (!list_empty(head)) {
				struct nat_mapping *map = NULL, *q;
				list_for_each_entry_safe(map, q, head, list) {
					if (now - map->update_time > TCP_ESTABLISHED_TIMEOUT || is_flow_finished(&(map->conn))) {
						nat.assigned_ports[map->external_port] = 0;
						list_delete_entry(&(map->list));
						free(map);
					} 
				}
			}
		}
		pthread_mutex_unlock(&nat.lock);
		sleep(1);
	}

	return NULL;
}

// Helper func: convert an ip str to u32.
u32 ip_str_to_u32(char *str) {
	
	int p1, p2, p3, p4;

	char *ptr1 = strchr(str, '.');
	char sp1[5] = {0};
	memcpy(sp1, str, ptr1 - str);
	p1 = atoi(sp1);
	str = ptr1 + 1;

	char *ptr2 = strchr(str, '.');
	char sp2[5] = {0};
	memcpy(sp2, str, ptr2 - str);
	p2 = atoi(sp2);
	str = ptr2 + 1;

	char *ptr3 = strchr(str, '.');
	char sp3[5] = {0};
	memcpy(sp3, str, ptr3 - str);
	p3 = atoi(sp3);
	str = ptr3 + 1;

	char *ptr4 = strchr(str, ':');
	char sp4[5] = {0};
	memcpy(sp4, str, ptr4 - str);
	p4 = atoi(sp4);
	str = ptr4 + 1;

	u32 ip;
	ip = p1 & 0xff;
	ip = (ip << 8) | (p2 & 0xff);
	ip = (ip << 8) | (p3 & 0xff);
	ip = (ip << 8) | (p4 & 0xff);

	return ip;
}

int parse_config(const char *filename)
{
	// fprintf(stdout, "TODO: parse config file, including i-iface, e-iface (and dnat-rules if existing).\n");
	FILE *fp = fopen(filename, "r");
	char buf[200];
	memset(buf, 0, sizeof(buf));

	while (fgets(buf, sizeof(buf), fp)) {
		if (strstr(buf, "internal-iface:")) {
			char *ptr = strstr(buf, "internal-iface:");
			char *newline = strchr(buf, '\n');
			newline[0] = '\0';
			nat.internal_iface = if_name_to_iface(ptr + 16);
		} else if (strstr(buf, "external-iface:")) {
			char *ptr = strstr(buf, "external-iface");
			char *newline = strchr(buf, '\n');
			newline[0] = '\0';
			nat.external_iface = if_name_to_iface(ptr + 16);
		} else if (strstr(buf, "dnat-rules:")) {
			char *ptr = strstr(buf, "dnat-rules:");
			struct dnat_rule *rule = (struct dnat_rule*)malloc(sizeof(struct dnat_rule));
			ptr += 12;
			rule->external_ip = ip_str_to_u32(ptr);
			ptr = strchr(ptr, ':') + 1;
			rule->external_port = atoi(ptr);
			ptr = strstr(ptr, "->") + 3;
			rule->internal_ip = ip_str_to_u32(ptr);
			ptr = strchr(ptr, ':') + 1;
			rule->internal_port = atoi(ptr);
			init_list_head(&rule->list);
			list_add_tail(&rule->list, &nat.rules);
		}
		memset(buf, 0, sizeof(buf)); 
	}

	struct dnat_rule *rule;
	list_for_each_entry(rule, &nat.rules, list)
	{
		printf("1: %x:%d,%x:%d\n", rule->external_ip,rule->external_port, rule->internal_ip, rule->internal_port);
	}
	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	// fprintf(stdout, "TODO: release all resources allocated.\n");
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct list_head *head = &nat.nat_mapping_list[i];
		struct nat_mapping *entry, *q;
		list_for_each_entry_safe(entry, q, head, list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);
	pthread_mutex_unlock(&nat.lock);
}
