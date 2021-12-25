#include <limits.h>
#include <gtest/gtest.h>
extern "C" {
#include "../router.h"
#include "../routing_table.h"
}

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

struct rte_ether_addr port_id_to_mac[10];

void init() {
    // create dummy mac addresses
    for (int i = 0; i < 10; ++i) {
        for (int a = 0; a < 6; ++a) {
            port_id_to_mac[i].addr_bytes[a] = (uint8_t) i*10;
        }
    }

    destruct_routing_table();
}

void check_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d, int next_hop) {
	int ip = RTE_IPV4(a,b,c,d);
	struct routing_table_entry* info = get_next_hop(ip);
	ASSERT_TRUE(info != nullptr) << "entry for " << (int) a << "." << (int) b << "." << (int) c << "." << (int) d << " is null";
	EXPECT_EQ(next_hop, info->dst_port) << ip << " failed";
	EXPECT_EQ(0, memcmp(&info->dst_mac, &port_id_to_mac[next_hop], sizeof(struct rte_ether_addr))) << ip << " failed";
	//print_routing_table_entry(info);
}

TEST(VERY_SIMPLE_TEST, SIMPLE_ADDRESSES) {
    init();

	// init routing table stuff
	printf("Try to add routes.\n");
	add_route(RTE_IPV4(10,0,40,10), 32, &port_id_to_mac[1], 1);
	add_route(RTE_IPV4(10,0,10,0), 24, &port_id_to_mac[0], 0);
	printf("Routes added.\n");

	// call once before test
	build_routing_table();

	// test cases
	check_address(10, 0, 40, 10, 1);

	EXPECT_EQ(nullptr, get_next_hop(RTE_IPV4(10,0,9,255)));
	for(int i = 0; i < 256; ++i) {
		check_address(10, 0, 10, i%256, 0);
	}
	EXPECT_EQ(nullptr, get_next_hop(RTE_IPV4(10,0,11,0)));
}

TEST(VERY_SIMPLE_TEST, EXTENSIVE_ADRESSES) {
    init();

    printf("Adding routes\n");
    add_route(RTE_IPV4(10,0,10,0), 24, &port_id_to_mac[0], 0);
    add_route(RTE_IPV4(10,0,40,10), 32, &port_id_to_mac[1], 1);
    add_route(RTE_IPV4(10,0,11,0), 24, &port_id_to_mac[3], 3);
    add_route(RTE_IPV4(10,0,10,128), 25, &port_id_to_mac[4], 4);
    add_route(RTE_IPV4(10,0,10,132), 30, &port_id_to_mac[5], 5);

    build_routing_table();

    printf("CHECKING /32\n");
    EXPECT_EQ(nullptr, get_next_hop(RTE_IPV4(10, 0, 40, 9)));
    check_address(10, 0, 40, 10, 1);
    EXPECT_EQ(nullptr, get_next_hop(RTE_IPV4(10, 0, 40, 11)));

    printf("CHECKING /24\n");
    EXPECT_EQ(nullptr, get_next_hop(RTE_IPV4(10,0,9,255)));
    for(int i = 0; i < 256; ++i) {
        uint8_t next_hop = 0;

        if (i >= 128) {
            next_hop = 4;
            if (i >= 132 && i <= 135) {
                next_hop = 5;
            }
        }

        check_address(10, 0, 10, i%256, next_hop);
    }

    for (int i = 0; i < 256; i++) {
        check_address(10, 0, 11, i%256, 3);
    }
    EXPECT_EQ(nullptr, get_next_hop(RTE_IPV4(10,0,12,0)));
}

int main(int argc, char* argv[]) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();

}

