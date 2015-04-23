//
// Created by lhunker on 4/23/15.
//

#include "nfq_router.h"

namespace aitf {
    void nfq_router::handle_aitf_pkt(AITFPacket *) {
        //TODO implement function
    }

    void nfq_router::update_rr(struct iphdr *, Flow) {
        //TODO implement function
    }

    bool nfq_router::check_filters() {
        //TODO implement
        return false;
    }
}