#ifndef _UTILS_H_
#define _UTILS_H_

#include "skel.h"
#include "queue.h"

/* Numarul maxim de intrari in Routing Table*/
#define MAX_ENTRIES 100000
/* Numarul maxim de intrar in ARP Cache */
#define MAX_ARP_ENTRIES 15
/* Octetii de offset pentru packetul ICMP in caz de eroare*/
#define ICMP_ERROR_OFFSET 64

/**
 * @brief Structura care are rolul de a pastra informatia necesara
 * pentru un packet care se afla in asteptare de arp reply
 */
struct arp_queue_entry{
    packet p;
    uint32_t ip;
	int interface;
};

/**
 * @brief Functie de comparare pentru doua intrari in Routing Table
 * 
 * @param p primul struct route_table_entry *
 * @param q al doilea struct route_table_entry *
 * @return diferenta dintre cele doua
 */
int compare (const void *p, const void *q);

/**
 * @brief Functie care returneaza header-ul arp dintr-un packet
 * 
 * @param p packet-ul din care extragem header-ul ARP
 * @return Header-ul ARP sau NULL in caz de vreo eroare
 */
struct arp_header* get_arp_header(packet* p);

/**
 * @brief Functie care returneaza ICMP header dintr-un packet
 * 
 * @param p packetul
 * @return Header ICMP sau NULL in caz ca protocolul peste IP nu e ICMP 
 */
struct icmphdr * get_icmp_hdr(packet *p);

/**
 * @brief Verifica daca mac-ul destinatie al packet-ului
 * este pentru acest dispozitiv
 * 
 * @param p packet
 * @return 0 - nu e pentru router, 1 - pentru router
 */
int check_packet_dest_mac(packet *p);

/**
 * @brief Verifica daca packet-ul este pentru router
 * 
 * @param p packet-ul
 * @return int 1 -> Da, 0 -> caz contrar
 */
int check_if_for_router(packet *p);

/**
 * @brief Primeste un packet(cu ARP Request in el) si construieste un ARP Reply
 * 
 * @param p packet-ul
 */
void generate_arp_reply(packet *p);

/**
 * @brief Functie care genereaza packet ARP request
 * 
 * @param daddr ip-ul destinatiei
 * @param interface interfata prin care se va transmite packetul
 * @return packet-ul generat
 */
void generate_arp_request(uint32_t daddr, int next_interface, packet * p);

/**
 * @brief Functie care trimite packetele din coada care asteapta ARP Reply
 * 
 * @param arp_reply_hdr packet-ul ARP Reply primit
 * @return queue noua coada
 */
queue send_waiting_packets(struct arp_header* arp_reply_hdr);

/**
 * @brief Functie care creeaza un packet ICMP
 * 
 * @param p packet-ul in care vom scrie (trebuie sa fie copie a unui packet cu 
 * date vechi in el)
 * @param type tipul packetului ICMP
 * @param code codul packetului ICMP
 */
void generate_icmp(packet *p, uint8_t type, u_int8_t code);

/**
 * @brief Aflarea index-ului din cache-ul arp a ip-ului
 * 
 * @param ip 
 * @return int -> indexul din arp cache sau -1 in caz de inexistenta
 */
int get_arp_entry(uint32_t ip);

/**
 * @brief Aflarea longest-prefix-match. Se face binary search pe rtable
 * 
 * @param dest_ip adresa ip a destinatiei
 * @return int indexul celei mai bune rute / -1 in caz de esec
 */
int calculate_best_route(uint32_t dest_ip);

/**
 * @brief Calcularea checksum dupa RFC 1624
 * 
 * @param old_checksum valoarea veche a checksumului
 * @param old_value valoarea veche a field-ului modificat (16 bit)
 * @param new_value valoarea noua a field-ului modificat (16 bit)
 * @return uint16_t checksumul nou
 */
uint16_t rfc_1624(uint16_t old_checksum, uint16_t old_value, uint16_t new_value);

#endif