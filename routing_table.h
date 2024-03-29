#ifndef ROUTING_TABLE_H__
#define ROUTING_TABLE_H__

#include <stdbool.h>

#include <rte_config.h>
#include <rte_ether.h>

// build a new routing table
void add_route(uint32_t ip_addr, uint8_t prefix, struct rte_ether_addr* mac_addr, uint8_t port);
void print_routes();
void print_port_id_to_mac();
void build_routing_table();
void print_next_hop_tab();

/**
 * This is non standard, but maybe handy for your CI setup, to run multiple test vectors consecutively.
 */
void destruct_routing_table();

struct routing_table_entry {
	struct rte_ether_addr dst_mac;
	uint8_t dst_port;
};

void print_routing_table_entry(struct routing_table_entry* info);

struct routing_table_entry* get_next_hop(uint32_t ip);

#endif

