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

struct device_config {
    uint8_t port_id;
    uint32_t ip_address;
    uint8_t device_count;
};

int validate_ipv4(struct rte_mbuf* buf, struct rte_ether_hdr* eth_hdr, struct rte_ipv4_hdr* ipv4_hdr) {
    uint16_t expected_cksum;
    uint16_t cksum;
    uint8_t version;
    uint16_t total_length;

    // RFC 1812 5.2.2 IP Header Validation
    //   (1) The packet length reported by the Link Layer must be large enough
    //        to hold the minimum length legal IP datagram (20 bytes).
    //
    //   (2) The IP checksum must be correct.
    //
    //   (3) The IP version number must be 4.  If the version number is not 4
    //        then the packet may be another version of IP, such as IPng or
    //        ST-II.
    //
    //   (4) The IP header length field must be large enough to hold the
    //        minimum length legal IP datagram (20 bytes = 5 words).
    //
    //   (5) The IP total length field must be large enough to hold the IP
    //        datagram header, whose length is specified in the IP header
    //        length field.

    assert(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4));

    // check for requirement (1)
    if (rte_pktmbuf_data_len(buf) < (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))) {
        printf("IPv4 buf length doesn't work out!\n");
        return -1;
    }

    // now it's safe to access ipv4_hdr!

    // check for requirement (2)
    expected_cksum = rte_be_to_cpu_16(ipv4_hdr->hdr_checksum);
    ipv4_hdr->hdr_checksum = 0; // "The checksum field must be set to 0 by the caller."
    cksum = rte_ipv4_cksum(ipv4_hdr);
    if (cksum != expected_cksum) {
        printf("IPv4 checksum didn't match: %d vs expected %d\n", cksum, expected_cksum);
        return -1;
    }
    ipv4_hdr->hdr_checksum = rte_cpu_to_be_16(expected_cksum); // TODO is this restoring needed?

    // check for requirement (3)
    version = (uint8_t) (ipv4_hdr->version_ihl & ~RTE_IPV4_HDR_IHL_MASK);
    if (version != 0x04) {
        printf("IPv4 version didn't match: %d vs expected 0x04\n", version);
        return -1;
    }

    // check for requirement (4)
    if (rte_ipv4_hdr_len(ipv4_hdr) < 20) {
        printf("IPv4 IHL encountered illegal value: %d\n", rte_ipv4_hdr_len(ipv4_hdr));
        return -1;
    }

    // check for requirement (5)
    total_length = rte_be_to_cpu_16(ipv4_hdr->total_length);
    // TODO we don't look any layer further, so we can't really verify,
    //   if the total_length field is properly set to accommodate the header of the next layer(?)

    // Additionally, the router SHOULD verify that the packet length
    //   reported by the Link Layer is at least as large as the IP total
    //   length recorded in the packet's IP header.  If it appears that the
    //   packet has been truncated, the packet MUST be discarded, the error
    //   SHOULD be logged, and the router SHOULD respond with an ICMP
    //   Parameter Problem message whose pointer points at the IP total length
    //   field.
    if (rte_pktmbuf_data_len(buf) < sizeof(struct rte_ether_hdr) + total_length) {
        printf("IPv4 total_length was reported bigger than the whole segment: %hu vs %lu\n",
               rte_pktmbuf_data_len(buf),
               sizeof(struct rte_ether_hdr) + total_length);
        return -1;
    }
    return 0;
}

int handle_ipv4(
    struct device_config* config,
    struct rte_mbuf* buf,
    struct rte_ether_hdr* eth_hdr,
    struct rte_ipv4_hdr* ipv4_hdr
) {
    uint32_t dst_addr;
    struct routing_table_entry* routing_entry;

    if (ipv4_hdr->time_to_live == 1) { // will be decreased to 0
        printf("IPv4 dropping packet due to ttl being 0\n");
        return -1;
    }

    dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

    routing_entry = get_next_hop(dst_addr);
    if (routing_entry == NULL) {
        printf("IPv4 couldn't find a routing entry for dst: %u\n", dst_addr);
        return -1;
    }

    // copy our eth address into the s_addr field!
    rte_eth_macaddr_get(config->port_id, &eth_hdr->s_addr);
    // set the d_addr field to the dst_mac of the routing entry!
    eth_hdr->d_addr = routing_entry->dst_mac;

    // RFC 1812 5.3.1 Time to Live (TTL)
    ipv4_hdr->time_to_live -= 1; // TODO ttl shouldn't matter for the cksum right?

    // "You can assume that all links have the same MTU, handling fragmentation is not required."
    // => if packet got to us, we know it was smaller than the MTU, according to above statement
    //  the packet is also smaller than any outgoing MTUs.

    // packet from port i is sent to the tx queue i of the destination port
    while(!rte_eth_tx_burst(routing_entry->dst_port, config->port_id, &buf, 1));
    return 0;
}

int handle_arp(
    struct device_config* config,
    struct rte_mbuf* buf,
    struct rte_ether_hdr* eth_hdr,
    struct rte_arp_hdr* arp_hdr
) {
    struct rte_arp_ipv4* arp_ipv4;

    assert(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP));

    if (rte_pktmbuf_data_len(buf) < (sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))) {
        printf("ARP buf length doesn't work out!\n");
        return -1;
    }

    if (rte_be_to_cpu_16(arp_hdr->arp_hardware) != RTE_ARP_HRD_ETHER) {
        printf("ARP unknown hardware\n");
        return -1;
    }

    if (rte_be_to_cpu_16(arp_hdr->arp_protocol) != RTE_ETHER_TYPE_IPV4) {
        printf("ARP unknown protocol\n");
        return -1;
    }

    arp_ipv4 = &arp_hdr->arp_data;

    // TODO hlen
    // TODO plen

    switch (rte_be_to_cpu_16(arp_hdr->arp_opcode)) {
    case RTE_ARP_OP_REQUEST:
        arp_ipv4->arp_tha = arp_ipv4->arp_sha;
        arp_ipv4->arp_tip = arp_ipv4->arp_sip;

        rte_eth_macaddr_get(config->port_id, &arp_ipv4->arp_sha);
        arp_ipv4->arp_sip = rte_cpu_to_be_16(config->ip_address); // TODO what about byte order?
        break;
    default:
        // we only respond to requests
        return -1;
    }

    return 0;
}

void handle_packet(struct device_config* config, struct rte_mbuf* buf) {
    int ret;
    struct rte_ether_hdr* eth_hdr;
    struct rte_ipv4_hdr* ipv4_hdr;
    struct rte_arp_hdr* arp_hdr;

    // TODO there is a difference between packet length and data (segment) length
    //  do we need to handle that? and how the hell is that to be handled?
    //  refer to rte_pktmbuf_pkt_len (also see last check in the IPv4 hdr validation)

    printf("Received mbuf data_length: %d\n", rte_pktmbuf_data_len(buf));
    if (rte_pktmbuf_data_len(buf) < sizeof(struct rte_ether_hdr)) {
        printf("ETH: Received way to less data!\n");
        rte_pktmbuf_free(buf);
        return;
    }
    eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);

    switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
    case RTE_ETHER_TYPE_IPV4:
        // accessing ipv4_hdr is only safe after `validate_ipv4` returned successfully!
        ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));

        ret = validate_ipv4(buf, eth_hdr, ipv4_hdr);
        if (ret != 0) {
            // TODO is this enough to free stuff?
            rte_pktmbuf_free(buf);
            return;
        }

        ret = handle_ipv4(config, buf, eth_hdr, ipv4_hdr);
        if (ret != 0) {
            rte_pktmbuf_free(buf);
            return;
        }
        break;
    case RTE_ETHER_TYPE_ARP:
        // accessing the arp_hdr isn't save before the length check!
        arp_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr*, sizeof(struct rte_arp_hdr));

        ret = handle_arp(config, buf, eth_hdr, arp_hdr);
        if (ret != 0) {
            rte_pktmbuf_free(buf);
            return;
        }
        break;
    default:
        rte_pktmbuf_free(buf);
        break;
    }
}

int router_thread(void* arg) {
    struct device_config* config = (struct device_config*) arg;
    struct rte_mbuf* bufs[64];

    while (1) {
        uint32_t rx = recv_from_device(config->port_id, config->device_count, bufs, 64);
        // recv_from_device already handles sleep after zero packets recv.

        for (uint32_t i = 0; i < rx; i++) {
            handle_packet(config, bufs[i]);
        }
    }
}

int parse_ip_addr(char* ip_address, uint32_t* dst) {
    char buf[MAX_IP_LENGTH] = {0};
    char dot_delimiter[] = ".";
    char* ptr;
    uint8_t fst;
    uint8_t snd;
    uint8_t trd;
    uint8_t fou;

    assert(strlen(ip_address) < MAX_IP_LENGTH);
    memcpy(buf, ip_address, MAX_IP_LENGTH - 1);

    ptr = strtok(buf, dot_delimiter);
    if (ptr == NULL) {
        return -1;
    }
    fst = atoi(ptr);

    ptr = strtok(NULL, dot_delimiter);
    if (ptr == NULL) {
        return -2;
    }
    snd = atoi(ptr);

    ptr = strtok(NULL, dot_delimiter);
    if (ptr == NULL) {
        return -3;
    }
    trd = atoi(ptr);

    ptr = strtok(NULL, dot_delimiter);
    if (ptr == NULL) {
        return -4;
    }
    fou = atoi(ptr);

    ptr = strtok(NULL, dot_delimiter);
    if (ptr != NULL) {
        return -5;
    }

    *dst = RTE_IPV4(fst, snd, trd, fou);
    return 0;
}

int parse_ip_cidr(char* ip_address_cidr, uint32_t* dst, uint8_t* prefix) {
    char buf[MAX_IP_CIDR_LENGTH] = {0};
    char slash_delimiter[] = "/";
    char* ip_address;
    char* prefix_num;
    char* ptr;
    int ret;

    assert(strlen(ip_address_cidr) < MAX_IP_CIDR_LENGTH);
    memcpy(buf, ip_address_cidr, MAX_IP_CIDR_LENGTH - 1);

    ip_address = strtok(buf, slash_delimiter);
    if (ip_address == NULL) {
        return -6;
    }

    prefix_num = strtok(NULL, slash_delimiter);
    if (prefix_num == NULL) {
        return -7;
    }

    ptr = strtok(NULL, slash_delimiter);
    if (ptr != NULL) {
        return -8;
    }

    ret = parse_ip_addr(ip_address, dst);
    if (ret != 0) {
        return ret;
    }

    *prefix = atoi(prefix_num);
    return 0;
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

uint8_t port_count() {
    uint8_t count = 0;
    struct port* entry = port_options;

    while (entry != NULL) {
        count++;
        if (count == 0) {
            printf("FATAL: Tried to support more than 255 ports!\n");
            exit(1);
        }
        entry = entry->next;
    }

    return count;
}

void free_ports_0(struct port* port) {
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

void free_routes_0(struct route* route) {
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
    const char comma_delimiter[] = ",";

    int opt;
    int ret;
    size_t len;
    char* ptr;

    struct port* port = NULL;
    struct route* route = NULL;

    while ((opt = getopt(argc, argv, "p:r:")) != EOF) {
        switch (opt) {
        case 'p':
            port = calloc(1, sizeof(struct port));

            // parse the interface id
            ptr = strtok(optarg, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'p' option(0)!\n");
                usage();
                free(port);
                return 1;
            }
            port->iface_port = atoi(ptr); // TODO replace atoi?


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

            ret = parse_ip_addr(ptr, &port->ip_address);
            if (ret != 0) {
                printf("ERR: Invalid format for 'p' option(3)!\n");
                usage();
                free(port);
                return 1;
            }

            ptr = strtok(NULL, comma_delimiter);
            if (ptr != NULL) {
                printf("ERR: Invalid format for 'p' option(4)!\n");
                usage();
                free(port);
                return 1;
            }


            // insert into the linked list!
            if (port_options == NULL) {
                port_options = port;
            } else {
                struct port* entry = port_options;
                while (entry->next != NULL) {
                    entry = entry->next;
                }
                entry->next = port;
            }
            port = NULL;
            break;
        case 'r':
            route = calloc(1, sizeof(struct route));

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

            ret = parse_ip_cidr(ptr, &route->route_ip_addr, &route->prefix);
            if (ret != 0) {
                printf("ERR: Invalid format for 'r' option(2)!\n");
                usage();
                free(route);
                return 1;
            }

            ptr = strtok(NULL, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'r' option(3)!\n");
                usage();
                free(route);
                return 1;
            }

            len = strlen(ptr);
            if (len != (RTE_ETHER_ADDR_FMT_SIZE - 1)) {
                printf("ERR: Invalid format for 'r' option(4)!\n");
                usage();
                free(route);
                return 1;
            }

            ret = rte_ether_unformat_addr(ptr, &route->next_hop.mac_address);
            if (ret != 0) {
                printf("ERR: Invalid format for 'r' option(5): %s!\n", rte_strerror(rte_errno));
                usage();
                free(route);
                return 1;
            }

            ptr = strtok(NULL, comma_delimiter);
            if (ptr == NULL) {
                printf("ERR: Invalid format for 'r' option(6)!\n");
                usage();
                free(route);
                return 1;
            }
            route->next_hop.port = atoi(ptr);

            ptr = strtok(NULL, comma_delimiter);
            if (ptr != NULL) {
                printf("ERR: Invalid format for 'r' option(7)!\n");
                usage();
                free(route);
                return 1;
            }

            if (route_options == NULL) {
                route_options = route;
            } else {
                struct route* entry = route_options;
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

        struct port* entry = port_options;
        do {
            printf(" - iface: %d  address: %d.%d.%d.%d\n", entry->iface_port, RTE_IPV4_UNFORMAT(entry->ip_address));
            entry = entry->next;
        } while (entry != NULL);
    } else {
        printf("ERR: router started without providing any ports\n");
        usage();
        return 1;
    }

    if (route_options != NULL) {
        printf("Configured ROUTES:\n");

        struct route* entry = route_options;
        char formatted_mac[RTE_ETHER_ADDR_FMT_SIZE] = {0};
        do {
            rte_ether_format_addr(formatted_mac, RTE_ETHER_ADDR_FMT_SIZE, &entry->next_hop.mac_address);

            printf(" - route: %d.%d.%d.%d/%d\t next_hop { mac: %s\tiface: %d }\n",
                   RTE_IPV4_UNFORMAT(route->route_ip_addr), route->prefix, formatted_mac, entry->next_hop.port);

            entry = entry->next;
        } while (entry != NULL);
    } else {
        printf("WARN: router started without providing any routes\n");
    }

    return 0;
}

void start_thread(struct port* port) {
    struct device_config* config = calloc(1, sizeof(struct device_config));
    config->port_id = port->iface_port;
    config->ip_address = port->ip_address;
    config->device_count = port_count();

    // worker_id start at 1(?), therefore we address them just by incrementing the iface_port by one.
    rte_eal_remote_launch(router_thread, config, port->iface_port + 1);
}

