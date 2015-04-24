#ifndef AITF_LEGACY_H
#define AITF_LEGACY_H

#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/common.h"

namespace aitf {
    class Server : public NFQ {
        public:
            Server();
            ~Server();
            void handle_aitf_pkt(AITFPacket *);
            void update_rr(unsigned char *, Flow *);

        private:
            FlowPaths *flows;
            bool check_filters();
    };
}

#endif
