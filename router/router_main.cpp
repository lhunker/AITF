//
// Created by lhunker on 4/24/15.
//

#include "nfq_router.h"

using aitf::endhost;

int main(int argc, char *argv[]) {
    if (argc < 2) {printf("Please provide an IP address!\n"); return 0;}
    vector<endhost> endhosts(1);
    struct endhost e;
    if (strcmp(argv[1], "10.4.10.2") == 0) {
        e.ip = 17433610;
        e.legacy = false;
    } else if (strcmp(argv[1], "10.4.10.3") == 0) {
        e.ip = 67765258;
        e.legacy = true;
    } else if (strcmp(argv[1], "10.4.10.7") == 0) {
        e.ip = 101319690;
        e.legacy = true;
    }
    endhosts.push_back(e);
    aitf::nfq_router nfq(endhosts, argv[1]);
    nfq.loop();

    return 0;
}
