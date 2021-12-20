#include "routing_table.h"

#include <rte_config.h>
#include <rte_ip.h>

// do nothing :)
void build_routing_table() {
}

static struct routing_table_entry hop_info1 = {
    .dst_mac = {.addr_bytes = {0x52, 0x54, 0x00, 0xff, 0x01, 0x00}},
    .dst_port = 0
};
static struct routing_table_entry hop_info2 = {
    .dst_mac = {.addr_bytes = {0x52, 0x54, 0x00, 0xff, 0x02, 0x00}},
    .dst_port = 1
};

struct routing_table_entry* get_next_hop(uint32_t ip) {
	if (ip == rte_cpu_to_be_32(RTE_IPV4(10,0,0,2))) {
		return &hop_info1;
	} else if (ip == rte_cpu_to_be_32(RTE_IPV4(192,168,0,2))) {
		return &hop_info2;
	} else {
		return NULL;
	}
}

void add_route(uint32_t ip_addr, uint8_t prefix, struct rte_ether_addr* mac_addr, uint8_t port) {
	// do nothing
}

