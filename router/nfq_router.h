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
        nfq_router();

        ~nfq_router();

        int handlePacket(struct nfq_q_handle*, int, unsigned char *, Flow *);

        int handle_aitf_pkt(struct nfq_q_handle*, int, AITFPacket *);

    private:
        bool check_filters();

        bool to_legacy_host();


    };

    //struct to hold information about a router's endhosts
    struct endhost {
        unsigned int ip;    //the host's ip address
        bool legacy;    //true if the host is legacy
    };
}

#endif //AITF_NFQ_ROUTER_H