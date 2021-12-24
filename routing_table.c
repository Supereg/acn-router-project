#include "routing_table.h"
#include "router.h" // TODO remove sometime

#include <math.h>
#include <rte_config.h>
#include <rte_ip.h>

static struct routing_table_entry hop_info1 = {
    .dst_mac = {.addr_bytes = {0x52, 0x54, 0x00, 0xff, 0x01, 0x00}},
    .dst_port = 0
};
static struct routing_table_entry hop_info2 = {
    .dst_mac = {.addr_bytes = {0x52, 0x54, 0x00, 0xff, 0x02, 0x00}},
    .dst_port = 1
};

static uint16_t TBL24[16777216] = {0}; // 2^24 entries
static uint8_t TBLlong[255*256] = {0};

struct routing_table_entry* hops;
int hops_size = -1;

struct added_route {
    uint32_t ip_addr;
    uint8_t prefix;
    struct rte_ether_addr mac_addr;
    uint8_t port;

    struct added_route* next;
};

bool building = true;
struct added_route* list_head;
int list_size = 0;

void mergesort(struct added_route array[], int low, int high);

uint32_t ones(uint8_t count) {
    uint32_t result = 0;

    for (uint8_t i = 0; i < count; i++) {
        result = result << 1;
        result += 1;
    }

    return result;
}

// do nothing :)
void build_routing_table() {
    struct added_route route_array[list_size];
    int next_free_element = 0;
    struct added_route* entry;
    struct added_route* tmp;
    uint8_t biggest_port = 0;

    building = false;
    memset(route_array, 0, list_size * sizeof(struct added_route));

    entry = list_head;
    while (entry != NULL) {
        route_array[next_free_element] = *entry;
        route_array[next_free_element].next = NULL;
        next_free_element++;

        if (entry->port > biggest_port) {
            biggest_port = entry->port;
        }

        tmp = entry;
        entry = entry->next;
        free(tmp);
    }
    // TODO assert list_size == next_free_element;

    mergesort(route_array, 0, list_size);

    hops_size = biggest_port;
    hops = calloc(hops_size, sizeof(struct rte_ether_addr));

    for (int i = 0; i < list_size; i++) {
        entry = &route_array[i];

        hops[entry->port].dst_port = entry->port;
        hops[entry->port].dst_mac = entry->mac_addr;

        uint8_t prefix_min_24 = entry->prefix > 24 ? 24 : entry->prefix;
        uint8_t perms = 24 - prefix_min_24;

        uint32_t neg_netmask_24 = ones(32  - prefix_min_24);

        uint32_t tbl_addr = (entry->ip_addr & ~neg_netmask_24) >> 8; // the first 24 bits
        uint8_t long_addr = entry->ip_addr & neg_netmask_24; // the last 8 bits

        ssize_t permutations = (ssize_t) pow(2, (24 - prefix_min_24));

        uint16_t next_hop_entry;
        if (long_addr == 0) {
            next_hop_entry = entry->port;
        } else {
            next_hop_entry = long_addr | 0x80; // TODO not exactly sure what we write into here?
        }

        printf("Route %d.%d.%d.%d/%d on port %d, TBL %d.%d.%d.%d LONG: %d\n",
               RTE_IPV4_UNFORMAT(entry->ip_addr), entry->prefix, entry->port, RTE_IPV4_UNFORMAT(tbl_addr), long_addr);

        for (ssize_t j = 0; j < permutations; j++) {
            TBL24[tbl_addr] = next_hop_entry;
            tbl_addr++;
        }
        // tbl_addr must not be used after this point!
        // TODO depending on the prefix size, fill TBLIST!2
    }
}

void add_route(uint32_t ip_addr, uint8_t prefix, struct rte_ether_addr* mac_addr, uint8_t port) {
    struct added_route* added_route;

    if (!building) {
        printf("Tried adding a new route after finished building routing table!\n");
        exit(1);
    }

    added_route = calloc(1, sizeof(struct added_route));
    if (added_route == NULL) {
        printf("Failed to initialize memory for `added_route`\n");
        exit(1);
    }

    added_route->ip_addr = ip_addr;
    added_route->prefix = prefix;
    added_route->mac_addr = *mac_addr;
    added_route->port = port;

    // prepend for efficient insert!
    added_route->next = list_head;
    list_head = added_route;
    list_size++;
}

struct routing_table_entry* get_next_hop(rte_be32_t ip) {
    uint32_t ip_address;
    uint32_t address_24;
    uint16_t tbl24_entry;
    struct routing_table_entry* routing_entry;

    ip_address = rte_be_to_cpu_32(ip);
    address_24 = (ip_address & ~ones(8)) >> 8;

    // TODO assert out of bounds access?
    tbl24_entry = TBL24[address_24];

    if ((tbl24_entry & 0x80) != 0) {
        printf("TBLlong entries aren't supported yet!\n");
        return NULL;
    }

    routing_entry = &hops[tbl24_entry];
    return routing_entry;
}

void merge(struct added_route array[], int low, int middle, int high) {
    struct added_route sorted[high - low + 1];

    int groupA = low;
    int groupB = middle + 1;

    for (int i = 0; i < (high - low + 1); i++) {
        if (groupA > middle) { // a is empty
            sorted[i] = array[groupB++];
        } else if (groupB > high) { // b is empty
            sorted[i] = array[groupA++];
        } else if (array[groupA].prefix < array[groupB].prefix) {
            sorted[i] = array[groupA++];
        } else {
            sorted[i] = array[groupB++];
        }
    }

    for (int i = 0; i < (high - low + 1); i++) {
        array[low + i] = sorted[i];
    }
}

void mergesort(struct added_route array[], int low, int high) {
    if (low >= high) {
        return;
    }

    int mid = (low + high) / 2;
    mergesort(array, low, mid);
    mergesort(array, mid + 1, high);
    merge(array, low, mid, high);
}
