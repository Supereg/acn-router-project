#include "router.h"

void boot() {
    struct port* port;
    uint8_t count = port_count();

    // configuring devices ...
    port = port_options;
    while (port != NULL) {
        // "... we need as many transmit (tx) queues per device as we have devices ..."
        configure_device(port->iface_port, count);
        port = port->next;
    }

    // starting threads for each device ...
    port = port_options;
    while (port != NULL) {
        start_thread(port);
        port = port->next;
    }
}

/**
 * Main function of the router.
 */
int main(int argc, char* argv[]) {
    int ret = parse_args(argc, argv);

    if (ret == 0) {
        boot();

        rte_eal_mp_wait_lcore();
    }

    free_ports();
    free_routes();
    return ret;
}

