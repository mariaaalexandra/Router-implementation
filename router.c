#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "queue.h"
#include "skel.h"

#define FAILURE -1
#define RTABLE_LEN_MAX (1 << 17)
#define ARPTABLE_LEN_MAX (1 << 7)
#define TRUE true
#define FALSE false

typedef struct route_table_entry route_table_entry;
typedef struct arp_entry arp_entry;
typedef struct arp_header arp_header;
typedef struct ether_header ether_header;
typedef struct iphdr iphdr;
typedef struct ethhdr ethhdr;

// Verify condition
#define MY_DIE(assertion, message)                                         \
  if (assertion) {                                                         \
    fprintf(stderr, "Error at line %d in file %s!\n", __LINE__, __FILE__); \
    perror(message);                                                       \
    exit(errno);                                                           \
  }

// Create route table and return it
// Also save the length
route_table_entry* create_route_table(char* file, int* length) {
  // Create it
  route_table_entry* tmp_rtable = NULL;
  tmp_rtable = calloc(RTABLE_LEN_MAX, sizeof(route_table_entry));
  MY_DIE(!tmp_rtable, "Couldn't create route table!");

  // Read it
  *length = read_rtable(file, tmp_rtable);
  return tmp_rtable;
}

// Initialize arp_table and return it
arp_entry* create_arp_table() {
  // Create it
  arp_entry* arp_table = NULL;
  arp_table = calloc(ARPTABLE_LEN_MAX, sizeof(arp_entry));
  MY_DIE(!arp_table, "Couldn't create arp table");
  return arp_table;
}

// Function used for sorting the rtable
int cmp_fct_sort(const void* a, const void* b) {
  int a_prefix = (uint32_t)((route_table_entry*)a)->prefix;
  int a_mask = (uint32_t)((route_table_entry*)a)->mask;
  int b_prefix = (uint32_t)((route_table_entry*)b)->prefix;
  int b_mask = (uint32_t)((route_table_entry*)b)->mask;

  if (b_prefix == a_prefix)
    return b_mask - a_mask;
  else
    return b_prefix - a_prefix;
}

// Return the rtable entry that matches our ip or NULL
route_table_entry* get_best_route(uint32_t dest_ip,
                                  route_table_entry* route_table,
                                  int route_table_length) {
  route_table_entry* ans = NULL;
  int idx = 0;

  while (route_table_length) {
    uint32_t prefix = (route_table[idx].mask & dest_ip);
    if (prefix == route_table[idx].prefix) {
      if (ans == NULL) {
        ans = &route_table[idx];
      } else if (ntohl(ans->mask) < ntohl(route_table[idx].mask)) {
        ans = &route_table[idx];
      }
    }

    --route_table_length;
    ++idx;
  }
  return ans;
}

// Send the packets that can be sent
void send_possible_packets(queue* waiting_packets, arp_header* arp_hdr,
                           route_table_entry* route_table,
                           int route_table_length) {
  // Variables
  packet* message = NULL;
  ether_header* eth_hdr = NULL;
  iphdr* ip_hdr = NULL;
  route_table_entry* best_entry = NULL;

  // Queue to hold unsent packets
  queue* remaining_packets_queue = queue_create();

  while (queue_empty(*waiting_packets) == FALSE) {
    // Get each packet
    message = (packet*)queue_deq(*waiting_packets);
    DIE(!message, "Couldn't get message!");

    // Get headers
    eth_hdr = (ether_header*)message->payload;
    DIE(!eth_hdr, "Couldn't get ethernet header!");
    ip_hdr = (iphdr*)(message->payload + sizeof(ether_header));
    DIE(!ip_hdr, "Couldn't get ip header!");

    // Get the route to send to
    best_entry = get_best_route(ip_hdr->daddr, route_table, route_table_length);

    // If there is nowhere to send, keep it
    if (best_entry->next_hop != arp_hdr->spa) {
      queue_enq(remaining_packets_queue, message);
    } else {  // forward it
      memcpy(eth_hdr->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
      memcpy(eth_hdr->ether_shost, arp_hdr->tha, sizeof(arp_hdr->tha));

      // Send packet
      message->interface = best_entry->interface;
      send_packet(message);
    }
  }

  // Keep unsent packets
  while (queue_empty(remaining_packets_queue) == FALSE) {
    message = queue_deq(remaining_packets_queue);
    queue_enq(waiting_packets, message);
  }
}

// Create an ARP request
void arp_request(route_table_entry* route) {
  // Get ether header
  struct ether_header* eth_hdr = NULL;
  eth_hdr = calloc(1, sizeof(ether_header));
  MY_DIE(!eth_hdr, "Couldn't create ethernet header in the arp request!");

  // Get mac
  uint8_t mac_addr[ETH_ALEN];
  get_interface_mac((*route).interface, mac_addr);
  memcpy(eth_hdr->ether_shost, mac_addr, ETH_ALEN);
  eth_hdr->ether_type = htons(ETHERTYPE_ARP);
  hwaddr_aton("ff:ff:ff:ff:ff", eth_hdr->ether_dhost);

  // Create header arp
  arp_header arp_hdr;
  arp_hdr.htype = htons(ARPHRD_ETHER);
  arp_hdr.ptype = htons(ETHERTYPE_IP);
  arp_hdr.op = htons(ARPOP_REQUEST);
  arp_hdr.hlen = ETH_ALEN;
  arp_hdr.plen = (1 << 2);
  memcpy(arp_hdr.tha, eth_hdr->ether_dhost, ETH_ALEN);
  memcpy(arp_hdr.sha, eth_hdr->ether_shost, ETH_ALEN);
  arp_hdr.tpa = (*route).next_hop;
  arp_hdr.spa = inet_addr(get_interface_ip((*route).interface));

  // Create the packet
  packet* new_packet = NULL;
  new_packet = (packet*)calloc(1, sizeof(packet));
  DIE(!new_packet, "Couldn't create new packet!");
  memcpy(new_packet->payload, eth_hdr, sizeof(ethhdr));
  memcpy(new_packet->payload + sizeof(ethhdr), &arp_hdr, sizeof(arp_header));
  new_packet->len = sizeof(arp_header) + sizeof(ethhdr);
  new_packet->interface = (*route).interface;

  // Send the created
  send_packet(new_packet);
}

// Swap two integers
int swap(int* a, int* b) {
  int tmp = *a;
  *a = *b;
  *b = tmp;
}

// Create an arp reply
void arp_reply(packet* message, ether_header* eth_hdr, arp_header* arp_hdr) {
  swap(&arp_hdr->tpa, &arp_hdr->spa);
  memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));
  get_interface_mac(message->interface, arp_hdr->sha);
  arp_hdr->op = htons(ARPOP_REPLY);
  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,
         sizeof(eth_hdr->ether_shost));
  memcpy(eth_hdr->ether_shost, arp_hdr->sha, sizeof(arp_hdr->sha));
}

// Check if header is received correcly
bool validate_checksum(iphdr* ip_hdr) {
  uint32_t old_check = ip_hdr->check;
  ip_hdr->check = 0;
  ip_hdr->check = ip_checksum((uint8_t*)ip_hdr, sizeof(iphdr));

  if (old_check != ip_hdr->check) {
    return FALSE;
  }

  return TRUE;
}

int main(int argc, char* argv[]) {
  init(argc - 2, argv + 2);

  // Variables
  int route_table_length = 0;
  int arp_table_length = 0;
  route_table_entry* route_table =
      create_route_table(argv[1], &route_table_length);
  qsort(route_table, route_table_length, sizeof(struct route_table_entry),
        cmp_fct_sort);
  arp_entry* arp_table = create_arp_table();
  queue waiting_packets = queue_create();  // Keep packets waiting to be sent
  ether_header* eth_hdr = NULL;
  iphdr* ip_hdr = NULL;
  arp_header* arp_hdr = NULL;
  arp_entry* cache_arp = NULL;
  arp_entry* tmp_arp = NULL;

  do {
    // Get packet
    packet message;
    int rc = get_packet(&message);
    MY_DIE(rc < 0, "Couldn't get packet!");

    // NULL headers
    ip_hdr = arp_hdr = NULL;
    eth_hdr = (ether_header*)message.payload;
    MY_DIE(!eth_hdr, "Couldn't get ether header!");

    switch (ntohs(eth_hdr->ether_type)) {
      // IP
      case ETHERTYPE_IP:
        // Get ip header
        ip_hdr = (iphdr*)(message.payload + sizeof(ethhdr));
        MY_DIE(!ip_hdr, "Couldn't get IP header!");

        // Checkings
        if (ip_hdr->ttl - 1 <= 0 || !validate_checksum(ip_hdr)) {
          continue;
        }

        // Get route
        route_table_entry* best_entry =
            get_best_route(ip_hdr->daddr, route_table, route_table_length);
        if (!best_entry) {  // drop packet
          continue;
        }

        // Else work with it
        message.interface = best_entry->interface;

        // Update checksum
        --ip_hdr->ttl;
        ip_hdr->check = ip_hdr->check - ~ip_hdr->ttl - ip_hdr->ttl;

        // Try go get arp
        bool found = false;
        for (int i = 0; i < arp_table_length; ++i) {
          if (arp_table[i].ip == ip_hdr->daddr) {
            cache_arp = &arp_table[i];
            found = true;
            goto out;
          }
        }
        if (!found) {
          goto exit;
        }
      out:

        if (cache_arp != NULL) {
          memcpy(eth_hdr->ether_dhost, &cache_arp->mac, ETH_ALEN);
          send_packet(&message);
        } else {  // Queue the packet to be send later
          packet new_pack;
        exit:
          memcpy(&new_pack, &message, sizeof(message));
          queue_enq(waiting_packets, &new_pack);
          arp_request(best_entry);
          continue;
        }

        break;

      // ARP
      case ETHERTYPE_ARP:
        // Get ARP header
        arp_hdr = NULL;
        arp_hdr = (arp_header*)(message.payload + sizeof(ether_header));
        MY_DIE(!arp_hdr, "Couldn't get arp header!");

        uint16_t reply_or_request = ntohs(arp_hdr->op);
        if (reply_or_request == ARPOP_REQUEST) {
          arp_reply(&message, eth_hdr, arp_hdr);
          send_packet(&message);
          continue;
        } else if (reply_or_request == ARPOP_REPLY) {
          // Create new arp entry
          tmp_arp = NULL;
          tmp_arp = calloc(1, sizeof(arp_entry));
          MY_DIE(!tmp_arp, "Can't create new entry in the arp table");

          // Copy header data and create the entry in the arp table
          memcpy(&tmp_arp->ip, &arp_hdr->spa, sizeof(arp_hdr->spa));
          memcpy(&tmp_arp->mac, &arp_hdr->sha, sizeof(arp_hdr->sha));
          arp_table[arp_table_length++] = *tmp_arp;

          // Dequeue the packet
          send_possible_packets(&waiting_packets, arp_hdr, route_table,
                                route_table_length);

          continue;
        }

        break;

      default:
        DIE(true, "Couldn't identify header!");
    }
  } while (true);
}
