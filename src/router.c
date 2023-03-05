#include "queue.h"
#include "skel.h"
#include "utils.h"

struct route_table_entry* rtable;
int rtable_size;

queue arp_queue;

struct arp_entry* arp_cache;
int arp_cache_entries;

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	/* Do not modify this line */
	init(argc - 2, argv + 2);
	/* Alocare si citire routing table */
	rtable = calloc(MAX_ENTRIES, sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);
	/* Sortare routing table */
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare);
	/* Alocare cache-ului arp */
	arp_cache = calloc(MAX_ARP_ENTRIES, sizeof(struct arp_entry));
	arp_cache_entries = 0;
	/* Crearea cozii de pachete arp */
	arp_queue = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		struct ether_header* eth_hdr = (struct ether_header *)m.payload;
		if(check_packet_dest_mac(&m) == 0) continue;
		if(eth_hdr->ether_type == htons(ETHERTYPE_IP)){
			struct iphdr* ip_hdr = (struct iphdr*)(m.payload + 
												sizeof(struct ether_header));
			if(check_if_for_router(&m) == 1){
				/* Packet pentru router */
				struct icmphdr * icmp_hdr = get_icmp_hdr(&m);
				/* Verificare daca e echo request */
				if(icmp_hdr != NULL){
					if(	icmp_hdr->type == ICMP_ECHO && 
						icmp_hdr->code == ICMP_REDIR_NET){
						/* Daca e echo request, cu datele din header-ul ICMP 
						 			Intoarcem echo reply */
						uint16_t old_check = icmp_hdr->checksum;
						icmp_hdr->checksum = 0;
						uint16_t new_check = icmp_checksum((uint16_t *)icmp_hdr, 
								ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
						if(old_check != new_check){
						 	continue;
						}
						/* Creare packet ICMP Reply */
						packet aux;
						memcpy(&aux, &m, sizeof(packet));
						generate_icmp(&aux, ICMP_ECHOREPLY, ICMP_REDIR_NET);
						send_packet(&aux);
						continue;
					}
					else {
						continue;
					}
				}
				else {
					continue;
				}
			}
			else{
				/* Packet nu pentru router
				   Verificare checksum */
				uint16_t old_check = ip_hdr->check;
				ip_hdr->check = htons(0);
				if(ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr)) 
								!= old_check){
					continue;
				}
				/* Verificare si actualizare TTL */
				if(ip_hdr->ttl <= 1){
					/* Daca TTL <= 1 -> Trimite ICMP cu "Time Exceeded" */
					packet aux;
					memcpy(&aux, &m, sizeof(packet));
					generate_icmp(&aux, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
					send_packet(&aux);
					continue;
				} else {
					/* Recalculare checksum */
					ip_hdr->check = rfc_1624(old_check, 
											(uint16_t)(ip_hdr->ttl),
											(uint16_t)(ip_hdr->ttl));
					ip_hdr->ttl--;
				}
				/* Cautare in tabela de rutare */
				int best_route_index = calculate_best_route(ip_hdr->daddr);

				if(best_route_index == -1){
					/* Daca nu gaseste nimic -> 
					   Trimite ICMP cu "Destination unreachable" */
					packet aux;
					memcpy(&aux, &m, sizeof(packet));
					generate_icmp(&aux, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
					send_packet(&aux);
					continue;
				}
				
				/* Rescriere adrese din header ETHERNET
				   Cautare in ARP cache */
				int arp_entry = get_arp_entry(rtable[best_route_index].next_hop);
				if(arp_entry == -1){
					/* Daca nu e in cache, se salveaza pachetul in coada */
					struct arp_queue_entry* entry = (struct arp_queue_entry*)
									calloc(1, sizeof(struct arp_queue_entry));
					entry->ip = rtable[best_route_index].next_hop;
					entry->p = m;
					entry->interface = rtable[best_route_index].interface;
					queue_enq(arp_queue, entry);
					/* Generare si trimitere pachet ARP Request */
					packet arp_request;
					generate_arp_request(rtable[best_route_index].next_hop, 
										rtable[best_route_index].interface, 
										&arp_request);
					send_packet(&arp_request);
					continue;
				}
				else{
					/* S-a gasit in ARP Cache -> facem forward */
					memcpy(eth_hdr->ether_dhost, arp_cache[arp_entry].mac, 
							ETH_ALEN);
					uint8_t mac[ETH_ALEN];
					get_interface_mac(rtable[best_route_index].interface, mac);
					memcpy(eth_hdr->ether_shost, mac, ETH_ALEN);
					m.interface = rtable[best_route_index].interface;
					send_packet(&m);
					continue;
				}
			}
		}
		else if(eth_hdr->ether_type == htons(ETHERTYPE_ARP)){
			struct arp_header* arp_hdr = get_arp_header(&m);
			if(arp_hdr != NULL) {
				/* Salveaza in cache-ul routerului de la cine a venit packetul */
				arp_cache[arp_cache_entries].ip = arp_hdr->spa;
				memcpy(arp_cache[arp_cache_entries].mac, arp_hdr->sha, ETH_ALEN);
				arp_cache_entries++;
				/* Verificare opcode ARP */
				if(ntohs(arp_hdr->op) == ARPOP_REQUEST){
					/* Daca e ARP Request -> construieste ARP Reply si trimite */
					packet aux;
					memcpy(&aux, &m, sizeof(packet));
					generate_arp_reply(&aux);
					send_packet(&aux);
					continue;
				} else if(ntohs(arp_hdr->op) == ARPOP_REPLY){
					/* Daca e ARP Reply -> construieste si trimite packetele 
					care asteapta */
					arp_queue = send_waiting_packets(arp_hdr);
					continue;
				}
			}
			else {
				continue;
			}
		}
	}
	free(arp_cache);
	free(rtable);
	while(!queue_empty(arp_queue)){
		queue_deq(arp_queue);
	}
	free(arp_queue);
	return 1;
}
