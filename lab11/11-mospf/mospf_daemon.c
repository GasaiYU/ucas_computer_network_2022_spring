#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"
#include "rtable.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define ROUTER_NUM 4

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);
	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}
	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);
void *updating_rtable_thread(void *param);
void sending_mospf_lsu();

void mospf_run()
{
	pthread_t hello, lsu, nbr, db, ur;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
	pthread_create(&ur, NULL, updating_rtable_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
	int pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
	iface_info_t *iface;
	while (1) {
		sleep(MOSPF_DEFAULT_HELLOINT);
		pthread_mutex_lock(&mospf_lock);

		list_for_each_entry(iface, &instance->iface_list, list) {
			char *packet = (char*)malloc(pkt_len);
			memset(packet, 0, pkt_len);

			struct ether_header *eh = (struct ether_header*)packet;
			struct iphdr *ih = (struct iphdr*)(packet + ETHER_HDR_SIZE);
			struct mospf_hdr *mh = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
			struct mospf_hello *hello = (struct mospf_hello*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
			
			u8 dhost[ETH_ALEN] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x05};
			eh->ether_type = htons(ETH_P_IP);
			memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
			memcpy(eh->ether_dhost, dhost, ETH_ALEN);

			ip_init_hdr(ih, iface->ip, MOSPF_ALLSPFRouters, pkt_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);

			mospf_init_hdr(mh, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);

			mospf_init_hello(hello, iface->mask);
			mh->checksum = mospf_checksum(mh);

			iface_send_packet(iface, packet, pkt_len);
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	// fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	while (1) {
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list) {
			mospf_nbr_t *nbr = NULL, *q;
			list_for_each_entry_safe(nbr, q, &iface->nbr_list, list) {
				nbr->alive++;
				if (nbr->alive > 3 * iface->helloint) {
					list_delete_entry(&nbr->list);
					free(nbr);
					iface->num_nbr--;
					sending_mospf_lsu();
				}
			}
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_database_thread(void *param)
{
	// fprintf(stdout, "TODO: link state database timeout operation.\n");
	while (1) {
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		mospf_db_entry_t *db_entry = NULL, *q;
		list_for_each_entry_safe(db_entry, q, &mospf_db, list) {
			db_entry->alive++;
			if (db_entry->alive > MOSPF_DATABASE_TIMEOUT) {
				list_delete_entry(&db_entry->list);
				free(db_entry);
			}
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}


void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	// fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
	pthread_mutex_lock(&mospf_lock);

	struct iphdr *ih = (struct iphdr*)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mh = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct mospf_hello *hello = (struct mospf_hello *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);

	int found = 0;
	mospf_nbr_t *nbr;
	list_for_each_entry(nbr, &iface->nbr_list, list) {
		if (nbr->nbr_id == ntohl(mh->rid)) {
			found = 1;
			nbr->alive = 0;
			break;
		}
	}

	if (!found) {
		mospf_nbr_t *new_nbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
		new_nbr->nbr_id = ntohl(mh->rid);
		new_nbr->nbr_ip = ntohl(ih->saddr);
		new_nbr->nbr_mask = ntohl(hello->mask);
		new_nbr->alive = 0;
		list_add_tail(&new_nbr->list, &iface->nbr_list);
		iface->num_nbr++;

		sending_mospf_lsu();
	}
	pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
	while (1) {
		sleep(MOSPF_DEFAULT_LSUINT);
		pthread_mutex_lock(&mospf_lock);
		sending_mospf_lsu();
		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void sending_mospf_lsu() {
	int nbr_sum = 0;
	iface_info_t *iface;
	list_for_each_entry (iface, &instance->iface_list, list) {
		if (!iface->num_nbr) {
			nbr_sum++;
		} else {
			nbr_sum += iface->num_nbr;
		}
	}

	struct mospf_lsa *ml_array = (struct mospf_lsa*)malloc(nbr_sum*MOSPF_LSA_SIZE);
	memset(ml_array, 0, nbr_sum*MOSPF_LSA_SIZE);
	
	iface = NULL;
	int pos = 0;
	// Fill in the array.
	instance->sequence_num++;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (!iface->num_nbr) {
			ml_array[pos].mask = htonl(iface->mask);
			ml_array[pos].network = htonl(iface->ip & iface->mask);
			ml_array[pos].rid = 0;
			pos++;
		} else {
			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				ml_array[pos].mask = htonl(nbr->nbr_mask);
				ml_array[pos].network = htonl(nbr->nbr_mask & nbr->nbr_ip);
				ml_array[pos].rid = htonl(nbr->nbr_id);
				pos++;
			}
		}
	}

	int pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + \
					nbr_sum * MOSPF_LSA_SIZE;
	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		mospf_nbr_t *nbr;
		list_for_each_entry(nbr, &iface->nbr_list, list) {
			char *packet = (char*)malloc(pkt_len);
			
			struct ether_header *eh = (struct ether_header*)packet;
			struct iphdr *ih = (struct iphdr*)(packet + ETHER_HDR_SIZE);
			struct mospf_hdr *mh = (struct mospf_hdr*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
			struct mospf_lsu *lh = (struct mospf_lsu*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE +MOSPF_HDR_SIZE);
			struct mospf_lsa *content = (struct mospf_lsa*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE+MOSPF_HDR_SIZE+MOSPF_LSU_SIZE);

			eh->ether_type = htons(ETH_P_IP);
			memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
			memset(eh->ether_dhost, 0x00, ETH_ALEN);

			ip_init_hdr(ih, iface->ip, nbr->nbr_ip, pkt_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
			
			mospf_init_hdr(mh, MOSPF_TYPE_LSU, pkt_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE, instance->router_id, instance->area_id);

			mospf_init_lsu(lh, nbr_sum);
			memcpy(content, ml_array, nbr_sum * MOSPF_LSA_SIZE);

			mh->checksum = mospf_checksum(mh);
			
			ip_send_packet(packet, pkt_len);
		}
	}
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
	pthread_mutex_lock(&mospf_lock);

	struct iphdr *ih= (struct iphdr*)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mh = (struct mospf_hdr*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct mospf_lsu *lh = (struct mospf_lsu*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
	struct mospf_lsa *content = (struct mospf_lsa*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);

	mospf_db_entry_t *db_entry;
	int found = 0;
	list_for_each_entry(db_entry, &mospf_db, list) {
		if (db_entry -> rid == ntohl(mh->rid)) {
			found = 1;
			if (ntohs(lh->seq) > db_entry->seq) {
				db_entry->seq = ntohs(lh->seq);
				db_entry->nadv = ntohl(lh->nadv);
				db_entry->alive = 0;
				for (int i = 0; i < db_entry->nadv; i++) {
					db_entry->array[i].mask = ntohl(content[i].mask);
					db_entry->array[i].network = ntohl(content[i].network);
					db_entry->array[i].rid = ntohl(content[i].rid);
				}
			}
		}
	}	

	if (!found) {
		mospf_db_entry_t *new_db_entry = (mospf_db_entry_t*)malloc(sizeof(mospf_db_entry_t));
		new_db_entry->rid = ntohl(mh->rid);
		new_db_entry->seq = ntohs(lh->seq);
		new_db_entry->nadv = ntohl(lh->nadv);
		new_db_entry->alive = 0;
		new_db_entry->array = (struct mospf_lsa*)malloc(new_db_entry->nadv * MOSPF_LSA_SIZE);

		for (int i = 0; i < new_db_entry->nadv; i++) {
			new_db_entry->array[i].network = ntohl(content[i].network);
			new_db_entry->array[i].mask = ntohl(content[i].mask);
			new_db_entry->array[i].rid = ntohl(content[i].rid);
		}

		list_add_tail(&new_db_entry->list, &mospf_db);
	}	

	pthread_mutex_unlock(&mospf_lock);

	lh->ttl--;
	if (lh->ttl > 0) {
		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list) {
			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				if (nbr->nbr_id != ntohl(mh->rid)) {
					char *sent_packet = (char*)malloc(len);
					struct iphdr *sent_ih = packet_to_ip_hdr(sent_packet);
					struct mospf_hdr *sent_mh = (struct mospf_hdr*)(sent_packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);

					memcpy(sent_packet, packet, len);
					sent_ih->saddr = htonl(iface->ip);
					sent_ih->daddr = htonl(nbr->nbr_ip);
					sent_ih->checksum = ip_checksum(sent_ih);
					sent_mh->checksum = mospf_checksum(sent_mh);

					ip_send_packet(sent_packet, len);
				}
			}
		}
	}
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

// Deal with graph
int graph[ROUTER_NUM][ROUTER_NUM] = {0};
int router[ROUTER_NUM] = {0};
int num = 0;

void init_graph(void) {
	memset(graph, INT8_MAX-1, sizeof(graph));

	mospf_db_entry_t *db;
	router[0] = instance->router_id;
	num = 1;
	list_for_each_entry(db, &mospf_db, list) {
		router[num++] = db->rid;
	}

	db = NULL;
	list_for_each_entry(db, &mospf_db, list) {
		int i, j;
		int u, v;
		for(i = 0; i < num; i++) {
			if(router[i] == db->rid)
				break;
		}
		u = i;
		for(i = 0; i < db->nadv; i++) {
			if(db->array[i].rid) {
				for(j = 0; j < num; j++) {
					if(router[j] == db->array[i].rid)
						break;
				}
				v = j;
				graph[u][v] = 1;
				graph[v][u] = 1;
			}
		}
	}
}


void dijkstra(int prev[], int dist[])
{
	int visit[ROUTER_NUM];
	for (int i = 0; i < ROUTER_NUM; i++) {
		dist[i] = INT8_MAX;
		prev[i] = -1;
		visit[i] = 0;
	}

	dist[0] = 0; 
	for (int i = 0; i < num; i++) {
		int j = -1;
		for (int k = 0; k < num; k++) {
			if(visit[k] == 0) {
				if(j == -1 || dist[k] < dist[j])
					j = k;
			}
		}
		int u = j;
		visit[u] = 1;
		for(int v = 0; v < num; v++) {
			if(!visit[v] && dist[u] + graph[u][v] < dist[v]) {
				dist[v] = dist[u] + graph[u][v];
				prev[v]= u;
			}
		}
	}
}

void *updating_rtable_thread(void *param) {
	while(1) {
		sleep(1);
		init_graph();
	
		int prev[4];
		int dist[4];
		dijkstra(prev, dist);

		int visit[4]= {0};
		visit[0] = 1;

		rt_entry_t *entry = (rt_entry_t *)malloc(sizeof(rt_entry_t));
		rt_entry_t *q = (rt_entry_t *)malloc(sizeof(rt_entry_t));
		list_for_each_entry_safe(entry, q, &rtable, list)
		{
			if(entry->gw) {
				remove_rt_entry(entry);
			}
		}

		for(int i = 0; i < num; i++) {
			int j = -1;
			for(int k = 0; k < num; k++) {
				if(!visit[k]) {
					if(j == -1 || dist[k] < dist[j])
					j = k;
				}
			}

			int u = j;
			visit[u] = 1;
			mospf_db_entry_t *db;
			list_for_each_entry(db, &mospf_db, list)
			{
				if(router[u] == db->rid) {
					int next_router;
					
					while(prev[u])
						u = prev[u];
					
					next_router = u;
					
					int found = 0;
					iface_info_t *iface;
					u32 gw;
					list_for_each_entry(iface, &instance->iface_list, list) {
						mospf_nbr_t *nbr;
						list_for_each_entry(nbr, &iface->nbr_list, list) {
							if(router[next_router] == nbr->nbr_id) {
								found = 1;
								gw = nbr->nbr_ip;
								break;
							}
						}
						if(found)
							break;
					}
					if(!found)
						break;
					
					for(int l = 0; l < db->nadv; l++) {
						rt_entry_t *rt_entry;
						found = 0;
						list_for_each_entry(rt_entry, &rtable, list)
						{
							if(rt_entry->dest == db->array[l].network && rt_entry->mask == db->array[l].mask)
							{
								found = 1;
								break;
							}
						}
						if(!found)
						{
							rt_entry_t *new_entry = new_rt_entry(db->array[l].network, db->array[l].mask, gw, iface);
							add_rt_entry(new_entry);
						}
					}
					
				}
			}
			
		}
		
	}
}
