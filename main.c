#include "router.h"

/**
 * Main function of the router.
 */
int main(int argc, char* argv[]) {
    int ret = parse_args(argc, argv);

    free_ports();
    free_routes();

    return ret;
}

