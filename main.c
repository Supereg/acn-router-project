#include "router.h"

/**
 * Main function of the router.
 */
int main(int argc, char* argv[]) {
    int ret = parse_args(argc, argv);

    if (ret == 0) {
        run_loop();
    }

    free_ports();
    free_routes();
    return ret;
}

