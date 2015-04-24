//
// Created by lhunker on 4/23/15.
//

#ifndef AITF_NFQ_ROUTER_H
#define AITF_NFQ_ROUTER_H

#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/common.h"

namespace aitf {
    class nfq_router : public NFQ {
    public:
        void update_rr(unsigned char *, Flow *);
        void handle_aitf_pkt(AITFPacket *);

    private:
        bool check_filters();
    };
}

#endif //AITF_NFQ_ROUTER_H
