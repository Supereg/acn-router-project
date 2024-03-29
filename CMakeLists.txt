CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT("acn-router")

SET(CMAKE_C_FLAGS "-Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -march=native")
SET(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu++11 -march=native")

SET(DPDK_LIBS
	rte_ethdev     rte_mbuf    rte_eal     rte_kvargs rte_ring  rte_mempool
	rte_cfgfile    rte_hash    rte_meter   rte_sched  rte_cmdline rte_bbdev
	rte_port       rte_net     rte_ip_frag rte_mempool_ring rte_telemetry
	rte_eventdev
)
SET(LINKER_OPTS -Wl,--whole-archive -Wl,--start-group ${DPDK_LIBS} -Wl,--end-group pthread dl rt m -Wl,--no-whole-archive)
INCLUDE_DIRECTORIES(
	/usr/local/include
)
LINK_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/dpdk/build/lib
)

# router
SET(PRJ router)
SET(SOURCES routing_table.c dpdk_init.c router.c)
ADD_EXECUTABLE(${PRJ} ${SOURCES} main.c)
TARGET_LINK_LIBRARIES(${PRJ} ${LINKER_OPTS})

# forwarder
SET(PRJ fwd)
ADD_EXECUTABLE(${PRJ} dpdk_init.c forwarder/fwd.c)
TARGET_LINK_LIBRARIES(${PRJ} ${LINKER_OPTS})

# test
SET(PRJ-TEST table-test)
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
ADD_EXECUTABLE(${PRJ-TEST} ${SOURCES} test/test.cc)
TARGET_LINK_LIBRARIES(${PRJ-TEST} -Wl,--start-group ${DPDK_LIBS} ${GTEST_LIBRARIES} -Wl,--end-group pthread dl rt)

