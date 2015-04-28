//
// Created by lhunker on 4/24/15.
//

#include "nfq_router.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {printf("Please provide an IP address!\n"); return 0;}
    aitf::nfq_router nfq(vector<aitf::endhost>(10), argv[1]);
    nfq.loop();

    return 0;
}
