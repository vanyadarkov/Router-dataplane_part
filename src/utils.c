#include "queue.h"
#include "skel.h"
#include "utils.h"

extern struct arp_entry* arp_cache;
extern int arp_cache_entries;

struct route_table_entry* rtable;
extern int rtable_size;

extern queue arp_queue;

int compare (const void *p, const void *q) {
	uint32_t a = ((struct route_table_entry *)p)->prefix;
    uint32_t b = ((struct route_table_entry *)q)->prefix;
	int res = b - a;
	if(res == 0){
		return ((struct route_table_entry *)q)->mask - 
                ((struct route_table_entry *)p)->mask;
	}
    return res;
}

struct arp_header* get_arp_header(packet *p){
    struct arp_header* arp_hdr = NULL;
    arp_hdr = (struct arp_header*)(p->payload + sizeof(struct ether_header));
    return arp_hdr;
}

struct icmphdr * get_icmp_hdr(packet* p){
    struct iphdr * ip_hdr = (struct iphdr *)
                                (p->payload + sizeof(struct ether_header));
    struct icmphdr * icmp_hdr = NULL;

    if(ip_hdr->protocol == 1){
        icmp_hdr = (struct icmphdr *)((void *)ip_hdr + sizeof(struct iphdr));
    }
    return icmp_hdr;
}

int check_packet_dest_mac(packet* p){
    int flag = 1;
    struct ether_header* eth_hdr = (struct ether_header*)p->payload;
    uint8_t mac[ETH_ALEN];
    get_interface_mac(p->interface, mac);
    /* Verificare daca MAC Dest == Interface MAC */
    for(int i = 0; i < ETH_ALEN; i++){
        if(eth_hdr->ether_dhost[i] != mac[i])
            flag = 0;
    }
    if(flag == 1) return 1;
    /* Daca nu corespunde, verifica daca e Broadcast */
    for(int i = 0; i < ETH_ALEN; i++){
        if(eth_hdr->ether_dhost[i] != 0xff)
            return 0;
    }
    return 1;
}


int check_if_for_router(packet *p){
    char * interface_ip = get_interface_ip(p->interface);
    struct in_addr int_ip;
    inet_aton(interface_ip, &int_ip);
    struct iphdr* ip_hdr = (struct iphdr*)
                            (p->payload + sizeof(struct ether_header));
    /* Daca ip-ul interfetei pe care a venit packetul egal cu ip destinatie 
       din packet -> packet pentru router */
    if(int_ip.s_addr == ip_hdr->daddr){
        return 1;
    }
    else return 0;
}

void generate_arp_reply(packet * p){
    struct ether_header * eth_hdr = (struct ether_header *)p->payload;
    struct arp_header * arp_hdr = get_arp_header(p);
    uint8_t this_mac[ETH_ALEN];
    uint8_t sender_mac[ETH_ALEN];
    /* Get this device MAC */
    get_interface_mac(p->interface, this_mac);
    /* Get sender MAC */
    memcpy(sender_mac, arp_hdr->sha, ETH_ALEN);
    /* Setting Op 2 (ARP Reply) */
    arp_hdr->op = htons(2);
    /* Seteaza acest device ca cel care a trimis ARP */
    memcpy(arp_hdr->sha, this_mac, ETH_ALEN);
    /* Seteaza device-ul care a trimis ARP ca ARP Target */
    memcpy(arp_hdr->tha, sender_mac, ETH_ALEN);
    uint32_t spa = arp_hdr->spa;
    uint32_t tpa = arp_hdr->tpa;
    /* Target IP = Sender IP (cel care va primi e cel care ne-a trimis) */
    arp_hdr->tpa = spa;
    /* Cel care trimite va fi cel care era target pentru ARP Request */
    arp_hdr->spa = tpa;
    /* Actualizeaza ETHERNET Header */
    memcpy(eth_hdr->ether_dhost, sender_mac, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, this_mac, ETH_ALEN);
    p->len = sizeof(struct ether_header) + sizeof(struct arp_header);
}

void generate_arp_request(uint32_t daddr, int next_interface, packet * p){
    memset(p, 0, sizeof(packet));
    struct ether_header * p_eth_hdr = (struct ether_header *)p->payload;
    /* Setez destinatia ca Broadcast */
    for(int i = 0; i < ETH_ALEN; i++){
        p_eth_hdr->ether_dhost[i] = 0xff;
    }
    uint8_t shost[ETH_ALEN];
    get_interface_mac(next_interface, shost);
    /* Setez sursa cu MAC-ul interfetei prin care trimitem */
    memcpy(p_eth_hdr->ether_shost, shost, ETH_ALEN);
    /* Setez ether_type ca ARP */
    p_eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    /* Creare arp_header */
    struct arp_header arp_hdr;
    arp_hdr.htype = htons(ARPHRD_ETHER);
    arp_hdr.ptype = htons(2048);
    arp_hdr.op = htons(1);
    arp_hdr.hlen = 6;
    arp_hdr.plen = 4;
    memcpy(arp_hdr.sha, shost, ETH_ALEN);
    memset(arp_hdr.tha, 0, ETH_ALEN);
    arp_hdr.spa = htonl(inet_network(get_interface_ip(next_interface)));
    arp_hdr.tpa = daddr;
    /* Scriere arp header in payload */
    memcpy(p->payload + sizeof(struct ether_header), 
            &arp_hdr, 
            sizeof(struct arp_header));
    p->interface = next_interface;
    p->len = sizeof(struct ether_header) + sizeof(struct arp_header);
}

queue send_waiting_packets(struct arp_header* arp_reply_hdr){
    queue aux = queue_create();
    while(!queue_empty(arp_queue)){
        struct arp_queue_entry *entry = queue_deq(arp_queue);
        if(entry->ip == arp_reply_hdr->spa){
            /* Daca e packet care astepta acest arp_reply
            il trimitem mai departe */
            entry->p.interface = entry->interface;
            uint8_t mac[ETH_ALEN];
            get_interface_mac(entry->interface, mac);
            struct ether_header* eth_hdr = (struct ether_header*)
                                            entry->p.payload;
            memcpy(eth_hdr->ether_shost, mac, ETH_ALEN);
            memcpy(eth_hdr->ether_dhost, arp_reply_hdr->sha, ETH_ALEN);
            send_packet(&(entry->p));
            free(entry);
        } else {
           /*  Daca nu e packet care asteapta
            Insereaza in coada auxiliara */
            queue_enq(aux, entry);
        }
    }
    // Intoarcem coada auxiliara
    return aux;
}

void generate_icmp(packet *p, uint8_t type, u_int8_t code){
    /* Imi fac pointeri catre zona din payload unde voi scrie
       Informatie pentru fiecare header */
    struct ether_header* eth_hdr = (struct ether_header *)p->payload;
	struct iphdr* ip_hdr = (struct iphdr *)
                            ((void*)eth_hdr + sizeof(struct ether_header));
    uint32_t daddr = ip_hdr->daddr;
    uint32_t saddr = ip_hdr->saddr;
    struct iphdr old_ip_hdr;
    struct icmphdr old_icmp_hdr;
    /* Salvam informatiile din vechile headere */
    memcpy(&old_ip_hdr, ip_hdr, sizeof(struct iphdr));
    memcpy(&old_icmp_hdr, 
            (void *)ip_hdr + sizeof(struct iphdr), 
            sizeof(struct icmphdr));
    struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0
	};
    /* Daca e echo reply -> trebuie sa pastram campurile 
    Sequence si ID din ICMP Header */
    if(type == ICMP_ECHOREPLY && code == ICMP_REDIR_NET){
        icmp_hdr.un.echo.id = old_icmp_hdr.un.echo.id;
        icmp_hdr.un.echo.sequence = old_icmp_hdr.un.echo.sequence;
    }
    else{
        // Daca e eroare -> trebuie sa specificam ca sursa am fost noi, nu cel
        // pentru care era packetul
        get_interface_ip(p->interface);
        struct in_addr int_ip;
        inet_aton(get_interface_ip(p->interface), &int_ip);
        daddr = int_ip.s_addr;
    }
    /* Salvam sursa si destinatia din ether header */
    uint8_t sha[ETH_ALEN];
    memcpy(sha, eth_hdr->ether_shost, ETH_ALEN);
    uint8_t dha[ETH_ALEN];
    memcpy(dha, eth_hdr->ether_dhost, ETH_ALEN);

    /* Setam datele din IP Header */
    ip_hdr->protocol = (uint8_t)1;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip_hdr->frag_off = 0;
    ip_hdr->id = htons(1);
    ip_hdr->tos = 0;
    ip_hdr->ttl = ip_hdr->ttl - 1;
    ip_hdr->check = 0;
    ip_hdr->daddr = saddr;
    ip_hdr->saddr = daddr;
    ip_hdr->check = htons(0);
    ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));
    icmp_hdr.checksum = 0;
    uint16_t new_check = icmp_checksum((uint16_t *)&icmp_hdr, 
                                        sizeof(struct icmphdr));
    icmp_hdr.checksum = new_check;
    /* Setez ether header */
    memcpy(eth_hdr->ether_dhost, sha, ETH_ALEN);
    memcpy(eth_hdr->ether_shost, dha, ETH_ALEN);

    void * payload = p->payload;
    payload += sizeof(struct ether_header) + sizeof(struct iphdr);
    /* Copiem toata informatia in packet */
    memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
    p->len = sizeof(struct ether_header) + 
            sizeof(struct iphdr) + 
            sizeof(struct icmphdr);
    if(!(type == 0 && code == 0)){
        /* Daca e eroare -> trebuie sa mai scriem peste ICMP Header, vechiul 
        IP si ICMP header */
        ip_hdr->tot_len += ICMP_ERROR_OFFSET;
        p->len = p->len + ICMP_ERROR_OFFSET;
        memcpy(payload + sizeof(struct icmphdr), 
                &old_ip_hdr, 
                sizeof(struct iphdr));
        payload += sizeof(struct icmphdr) + sizeof(struct iphdr);
        memcpy(payload, &old_icmp_hdr, sizeof(struct icmphdr));
        /* Recalculam checksumul fiindca avem mai multi octeti deja in packet */
        struct icmphdr * new_icmp = (struct icmphdr *)
            (p->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
        new_icmp->checksum = 0;
        new_icmp->checksum = icmp_checksum((uint16_t *)new_icmp,
                                     ip_hdr->tot_len - sizeof(struct iphdr));
    }
    /* Convertam total len-ul la network endianess */
    ip_hdr->tot_len = htons(ip_hdr->tot_len);
}

int get_arp_entry(uint32_t ip){
    for(int i = 0; i < arp_cache_entries; i++){
        if(arp_cache[i].ip == ip){
            return i;
        }
    }
    return -1;
}

int calculate_best_route(uint32_t dest_ip){
    int low = 0, high = rtable_size - 1;
    int mid = -2;
    uint32_t prefix = -1;
    /* Se cautam primul match */
    while(low <= high){
        mid = low + (high - low) / 2;
        prefix = rtable[mid].mask & dest_ip;
        if(rtable[mid].prefix == prefix){
           break;
        }
        else if(rtable[mid].prefix > prefix){
            low = mid + 1;
        }
        else high = mid - 1;
    }
    /* Daca s-a gasit */
    if(rtable[mid].prefix == prefix){
        /* Verificam daca nu e index 0 */
        if(mid == 0) return mid;
        if(rtable[mid - 1].prefix == prefix){
            /* Daca mai sus avem aceleasi prefixe */
            while(mid >= 0){
                /* Ne ducem mai sus */
                mid--;
                /* Verificam daca ne satisfac */
                if(rtable[mid].prefix > (dest_ip & rtable[mid].mask))
                    return mid + 1;
            }
        }
        else return mid;
    }
    return -1;
}

uint16_t rfc_1624(uint16_t old_checksum, uint16_t old_value, uint16_t new_value){
    /*
        HC  - old checksum in header
        C   - one's complement sum of old header
        HC' - new checksum in header
        C'  - one's complement sum of new header
        m   - old value of a 16-bit field
        m'  - new value of a 16-bit field

        HC' = HC - ~m - m'
    */
   return old_checksum - ~old_value - new_value;
}
