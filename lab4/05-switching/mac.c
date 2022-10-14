#include "mac.h"
#include "log.h"
#include "utils.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;

/* check if 2 u8 arrays are equal.*/
int check_u8_equal(u8 *u1, u8 *u2, int len) {
	for (int i = 0; i < len; i++) {
		if (u1[i] != u2[i]) {
			return 0;
		}
	}
	return 1;
}

void u8_cpy(u8 *dst, u8 *src, int len) {
	for (int i = 0; i < len; i++) {
		dst[i] = src[i];
	}
}

// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table. If not found, return null.
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	u8 hash_mac = hash8((char*)mac, ETH_ALEN);

	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry;
	list_for_each_entry(entry, &mac_port_map.hash_table[hash_mac], list) {
		if (check_u8_equal(entry -> mac, mac, ETH_ALEN)) {
			entry -> visited = time(NULL);
			pthread_mutex_unlock(&mac_port_map.lock);
			return entry -> iface;
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
	return NULL;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *new_mac_port_entry = (mac_port_entry_t*)safe_malloc(sizeof(mac_port_entry_t));
	bzero(new_mac_port_entry, sizeof(mac_port_entry_t));

	u8_cpy(new_mac_port_entry -> mac, mac, ETH_ALEN);
	new_mac_port_entry -> iface = iface;
	new_mac_port_entry -> visited = time(NULL);

	u8 hash_mac = hash8((char*)mac, ETH_ALEN);
	list_add_tail(&new_mac_port_entry->list, &mac_port_map.hash_table[hash_mac]);

	pthread_mutex_unlock(&mac_port_map.lock);
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	pthread_mutex_lock(&mac_port_map.lock);	
	mac_port_entry_t *mac_entry, *q;
	time_t now = time(NULL);
	int count = 0;

	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(mac_entry, q, &mac_port_map.hash_table[i], list) {
			if ((int)(now - mac_entry -> visited) > MAC_PORT_TIMEOUT) {
				list_delete_entry(&mac_entry -> list);
				free(mac_entry);
				count ++;
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);

	return count;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}
