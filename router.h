#ifndef ROUTER_H__
#define ROUTER_H__

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_launch.h>

#include <arpa/inet.h>

#include "dpdk_init.h"
#include "routing_table.h"

#define MAX_IP_LENGTH 16 // 4*3 + 3 + 1
#define MAX_IP_CIDR_LENGTH 19 // 4*3 + 3 + 1 + 2 + 1

/**
 * Specifies a port on the router.
 */
struct port {
    // The interface id of the router interface.
    uint8_t iface_port;
    // The routers ip address.
    uint32_t ip_address;

    // next Port in the linked list
    struct port* next;
};

/**
 * Specifies a route in the routing table.
 */
struct route {
    uint32_t route_ip_addr;
    uint8_t prefix;

    struct {
        struct rte_ether_addr mac_address;
        uint8_t port;
    } next_hop;

    // next Route in the linked list
    struct route* next;
};

uint8_t port_count();

void free_ports();
void free_routes();

void parse_route(char *route);

void run_loop();

int router_thread(void* arg);
int parse_args(int argc, char **argv);
void start_thread(struct port* port);

#define RTE_IPV4_A(ip) (((ip) >> 24) & 0xff)
#define RTE_IPV4_B(ip) (((ip) >> 16) & 0xff)
#define RTE_IPV4_C(ip) (((ip) >> 8) & 0xff)
#define RTE_IPV4_D(ip) ((ip) & 0xff)

#define RTE_IPV4_UNFORMAT(ip) RTE_IPV4_A(ip), RTE_IPV4_B(ip), RTE_IPV4_C(ip), RTE_IPV4_D(ip)

#endif

