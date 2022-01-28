#include "routing_table.h"
#include "router.h" // TODO remove sometime

#include <math.h>
#include <rte_config.h>
#include <rte_ip.h>

#define TBL24_SIZE 16777216 // 2^24 entries
#define TBL_LONG_SIZE (255*256)

/**
 * We encode non existent TBL24 entries with all ones except the most significant bit, which is set to zero.
 * This is basically a entry, which holds a next_hop_id (most significant bit is 1) but with all ones.
 * As we have 1 byte port ids, this is a non existent entry.
 *
 * For simplicity reasons, TBLlong uses the same value to indicate non-existent value.
 */
#define NON_EXISTENT_ENTRY 0x7FFF // 0b0111.1111.1111.1111

#define IS_TBL_LONG_PTR(tbl24_entry) ((tbl24_entry & 0x8000) != 0)
#define MAKE_TBL_LONG_PTR(tbl24_entry) (tbl24_entry | 0x8000)
#define UNWRAP_TBL_LONG_PTR(tbl24_entry) (tbl24_entry & NON_EXISTENT_ENTRY)

struct added_route {
    uint32_t ip_addr;
    uint8_t prefix;
    struct rte_ether_addr mac_addr;
    uint8_t port;

    struct added_route* next;
};

static uint16_t TBL24[TBL24_SIZE] = {0};
/**
 * We use uint16_t instead of uint8_t as we somehow need to encode non existent entries.
 * Any value bigger than UINT8_MAX is used to indicate a non-existent value.
 * Specifically, for simplicity reasons we use `NON_EXISTENT_ENTRY` (like in TBL24).
 */
static uint16_t TBLlong[TBL_LONG_SIZE] = {0};
static uint16_t next_tbl_long_index = 0;

/**
 * Lookup table for hops. We construct this dynamically based on the biggest port id we encounter.
 */
struct routing_table_entry* hops = NULL;
int max_hop_id = -1;

bool building = true;
struct added_route* list_head = NULL;

/**
 * You may call this to reset application state back to initialization.
 */
void destruct_routing_table() {
    struct added_route* entry;
    struct added_route* tmp;

    if (hops != NULL) {
        free(hops);
        hops = NULL;
    }
    max_hop_id = -1;

    entry = list_head;
    while (entry != NULL) {
        tmp = entry;
        entry = entry->next;
        free(tmp);
    }
    list_head = NULL;

    memset(TBL24, 0, TBL24_SIZE * sizeof(uint16_t));
    memset(TBLlong, 0, TBL_LONG_SIZE * sizeof(uint16_t));
    next_tbl_long_index = 0;

    building = true;
}

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
    struct added_route* entry;

    // step 0 is to init the tables
    for (int i = 0; i < TBL24_SIZE; i++) {
        TBL24[i] = NON_EXISTENT_ENTRY;
    }

    for (int i = 0; i < TBL_LONG_SIZE; ++i) {
        TBLlong[i] = NON_EXISTENT_ENTRY;
    }

    building = false;

    hops = calloc(max_hop_id + 1, sizeof(struct rte_ether_addr));
    if (hops == NULL) {
        printf("ERR: Failed to allocate `hops` memory!\n");
        exit(1);
    }

    entry = list_head;
    while (entry != NULL) {
        // write the hop num
        hops[entry->port].dst_port = entry->port;
        hops[entry->port].dst_mac = entry->mac_addr;

        uint32_t netmask = ~ones(32 - entry->prefix);
        uint32_t tbl_24_addr = (entry->ip_addr & netmask) >> 8;
        uint8_t tbl_long_addr = 0xFF & (entry->ip_addr & netmask);

        printf("Building route %d.%d.%d.%d/%d with port id %d\n", RTE_IPV4_UNFORMAT(entry->ip_addr), entry->prefix, entry->port);

        if (entry->prefix > 24) {
            uint16_t tbl_long_ptr;

            uint8_t lowest = tbl_long_addr + 0;
            uint8_t highest = tbl_long_addr + ones(32 - entry->prefix);

            // remember: due to our sorting above, we have the guarantee, that we are always just overwriting less specific routes

            uint16_t curren_tbl_entry = TBL24[tbl_24_addr];
            if (IS_TBL_LONG_PTR(curren_tbl_entry)) {
                tbl_long_ptr = UNWRAP_TBL_LONG_PTR(curren_tbl_entry);

                // we have an existent ptr to TBLlong, just write our (more specific) route into its according entries
                for (uint8_t j = lowest; j <= highest; j++) {
                    TBLlong[tbl_long_ptr + j] = entry->port;
                }
            } else { // we either have a non-existent entry, or a next hop id
                tbl_long_ptr = next_tbl_long_index;
                next_tbl_long_index += 256; // we always reserve the next 256 entries

                for (uint8_t j = 0; true; j++) {
                    if (j >= lowest && j <= highest) {
                        TBLlong[tbl_long_ptr + j] = entry->port;
                    } else {
                        // this writes either `NON_EXISTENT_ENTRY` or the current port id from TBL24
                        TBLlong[tbl_long_ptr + j] = curren_tbl_entry;
                    }

                    if (j == UINT8_MAX) {
                        break;
                    }
                }
            }

            TBL24[tbl_24_addr] = MAKE_TBL_LONG_PTR(tbl_long_ptr);
        } else {
            // we know entry.prefix is <= 24
            ssize_t permutations = (ssize_t) pow(2, (24 - entry->prefix));
            for (ssize_t j = 0; j < permutations; j++) {
                TBL24[tbl_24_addr + j] = entry->port;
            }
        }

        entry = entry->next;
    }

    printf("Finished building routing table!\n");
}

void add_route(uint32_t ip_addr, uint8_t prefix, struct rte_ether_addr* mac_addr, uint8_t port) {
    struct added_route* added_route;
    struct added_route* entry;

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

    if (added_route->port > max_hop_id) {
        max_hop_id = added_route->port;
    }

    // sorted insert into linked list
    if (list_head == NULL) {
        list_head = added_route;
    } else {
        struct added_route** entry_ptr;

        entry_ptr = &list_head;
        entry = list_head;
        for(;;) {
            if (added_route->prefix < entry->prefix) {
                added_route->next = entry;
                *entry_ptr = added_route;
                break;
            }

            if (entry->next == NULL) {
                entry->next = added_route;
                break;
            }

            entry_ptr = &entry->next;
            entry = entry->next;
        }
    }
}

struct routing_table_entry* get_next_hop(uint32_t ip) {
    uint32_t address_24;
    uint8_t address_8;
    uint16_t tbl24_entry;

    assert(!building && "Tried to retrieve next hop, though `build_routing_table` wasn't yet called!");

    address_24 = ip >> 8;
    address_8 = ip & 0xFF;

    assert(address_24 < TBL24_SIZE && "TBL24 index out of bounds!");
    tbl24_entry = TBL24[address_24];

    if (IS_TBL_LONG_PTR(tbl24_entry)) {
        uint16_t tbl_long_index = UNWRAP_TBL_LONG_PTR(tbl24_entry);
        uint16_t tbl_long_value = TBLlong[tbl_long_index + address_8];

        if (tbl_long_value > UINT8_MAX) {
            // non-existent route entry. also see `NON_EXISTENT_ENTRY`.
            return NULL;
        }

        return &hops[tbl_long_value];
    }


    if (tbl24_entry > UINT8_MAX) {
        // non-existent route entry. also see `NON_EXISTENT_ENTRY`.
        return NULL;
    }

    return &hops[tbl24_entry];
}
