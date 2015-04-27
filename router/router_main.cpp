//
// Created by lhunker on 4/24/15.
//

#include "nfq_router.h"

int main(int argc, char *argv[]) {
    aitf::nfq_router nfq(vector<aitf::endhost>(10));
    nfq.loop();

    return 0;
}
