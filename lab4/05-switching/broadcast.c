#include "base.h"
#include <stdio.h>

extern ustack_t *instance;

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	iface_info_t *iface_entry;
	list_for_each_entry(iface_entry, &instance -> iface_list, list) {
		if (iface_entry -> fd != iface -> fd)
			iface_send_packet(iface_entry, packet, len);
	}
}
