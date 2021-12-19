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
#include "router.h"

#define MAX_IP_LENGTH 16 // 4*3 + 3 + 1
#define MAX_IP_CIDR_LENGTH 19 // 4*3 + 3 + 1 + 2 + 1

/**
 * Specifies a Port on the router.
 */
struct Port {
    // The interface id of the router interface.
    uint8_t interfaceId;
    // The router ip address as a char array.
    char address[MAX_IP_LENGTH];

    // next Port in the linked list
    struct Port* next;
};

/**
 * Specifies a route in the routing table.
 */
struct Route {
    // The route in CIDR notation as a char array.
    char route[MAX_IP_CIDR_LENGTH];

    struct {
        struct rte_ether_addr mac_address;
        uint8_t dstInterfaceId;
    } next_hop;

    // next Route in the linked list
    struct Route* next;
};

struct Port* port_options = NULL;
struct Route* route_options = NULL;


int router_thread(void* arg) {
    return 1;
}

void parse_route(char *route) {
}

/**
 * Usage of applicaiton
 */
void usage() {
    printf("-p <port> -r <route>\n");
    printf("Parameters are formatted as follows:\n");
    printf("  port format:  <iface_id>,<ip_address>\n");
    printf("  route format: <route_cidr>,<next_hop_mac>,<next_hop_iface_id>\n");
}

void free_ports_0(struct Port* port) {
    if (port->next != NULL) {
        free_ports_0(port->next);
    }
    free(port);
}

// called from main.c
void free_ports() {
    if (port_options != NULL) {
        free_ports_0(port_options);
    }
}

void free_routes_0(struct Route* route) {
    if (route->next != NULL) {
        free_routes_0(route->next);
    }
    free(route);
}

// called from main.c
void free_routes() {
    if (route_options != NULL) {
        free_routes_0(route_options);
    }
}

int parse_args(int argc, char** argv) {
    static const char comma_delimiter[] = ",";

    int opt;
    size_t len;
    char* ptr;

    struct Port* port = NULL;
    struct Route* route = NULL;

    while ((opt = getopt(argc, argv, "p:r:")) != EOF) {
        switch (opt) {
        case 'p':
            port = calloc(1, sizeof(struct Port));

            // parse the interface id
            ptr = strtok(optarg, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'p' option(0)!\n");
                usage();
                free(port);
                return 1;
            }
            port->interfaceId = atoi(ptr); // TODO replace atoi?


            // parse the ip address
            ptr = strtok(NULL, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'p' option(1)!\n");
                usage();
                free(port);
                return 1;
            }

            len = strlen(ptr);
            assert(len < MAX_IP_LENGTH && "Invalid ip format!");
            if (len >= MAX_IP_LENGTH) {
                printf("ERR: Invalid format for 'p' option(2)!\n");
                usage();
                free(port);
                return 1;
            }
            memcpy(&port->address, ptr, len);

            ptr = strtok(NULL, comma_delimiter);
            if (ptr != NULL) {
                printf("ERR: Invalid format for 'p' option(3)!\n");
                usage();
                free(port);
                return 1;
            }


            // insert into the linked list!
            if (port_options == NULL) {
                port_options = port;
            } else {
                struct Port* entry = port_options;
                while (entry->next != NULL) {
                    entry = entry->next;
                }
                entry->next = port;
            }
            port = NULL;
            break;
        case 'r':
            route = calloc(1, sizeof(struct Route));

            ptr = strtok(optarg, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'r' option(0)!\n");
                usage();
                free(route);
                return 1;
            }

            len = strlen(ptr);
            if (len >= MAX_IP_CIDR_LENGTH) {
                printf("ERR: Invalid format for 'r' option(1)!\n");
                usage();
                free(route);
                return 1;
            }
            memcpy(&route->route, ptr, len);

            ptr = strtok(NULL, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'r' option(2)!\n");
                usage();
                free(route);
                return 1;
            }

            len = strlen(ptr);
            if (len != (RTE_ETHER_ADDR_FMT_SIZE - 1)) {
                printf("ERR: Invalid format for 'r' option(3)!\n");
                usage();
                free(route);
                return 1;
            }

            int ret = rte_ether_unformat_addr(ptr, &route->next_hop.mac_address);
            if (ret != 0) {
                printf("ERR: Invalid format for 'r' option(4): %s!\n", rte_strerror(rte_errno));
                usage();
                free(route);
                return 1;
            }

            ptr = strtok(NULL, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'r' option(5)!\n");
                usage();
                free(route);
                return 1;
            }
            route->next_hop.dstInterfaceId = atoi(ptr);

            ptr = strtok(NULL, comma_delimiter);
            if (ptr != NULL) {
                printf("ERR: Invalid format for 'r' option(6)!\n");
                usage();
                free(route);
                return 1;
            }

            if (route_options == NULL) {
                route_options = route;
            } else {
                struct Route* entry = route_options;
                while (entry->next != NULL) {
                    entry = entry->next;
                }
                entry->next = route;
            }
            route = NULL;
            break;
        default:
            printf("ERR: Unrecognized option %c %s\n", opt, optarg);
            usage();
            return 1;
        }
    }

    if (port_options != NULL) {
        printf("Configured PORTS:\n");

        struct Port* entry = port_options;
        do {
            printf(" - iface: %d  address: %s\n", entry->interfaceId, entry->address);
            entry = entry->next;
        } while (entry != NULL);
    } else {
        printf("ERR: router started without providing any ports\n");
        usage();
        return 1;
    }

    if (route_options != NULL) {
        printf("Configured ROUTES:\n");

        struct Route* entry = route_options;
        char formatted_mac[RTE_ETHER_ADDR_FMT_SIZE] = {0};
        do {
            rte_ether_format_addr(formatted_mac, RTE_ETHER_ADDR_FMT_SIZE, &entry->next_hop.mac_address);

            printf(" - route: %s\t next_hop { mac: %s\tiface: %d }\n", entry->route, formatted_mac, entry->next_hop.dstInterfaceId);

            entry = entry->next;
        } while (entry != NULL);
    } else {
        printf("WARN: router started without providing any routes\n");
    }

    return 0;
}

void start_thread(uint8_t port) {
}

