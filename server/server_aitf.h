#ifndef AITF_LEGACY_H
#define AITF_LEGACY_H

#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/common.h"
#include <vector>
#include <time.h>

namespace aitf {
    class FlowPaths {/*{{{*/
        public:
            FlowPaths();
            void add_flow(Flow);
            bool check_attack_threshold(Flow);
        private:
            int timeout;
            vector<Flow> route_ips;
            vector<int> pkt_count;
            vector<int> pkt_times;
            void reset_count(int);
    };/*}}}*/

    class Server : public NFQ {/*{{{*/
        public:
            Server();
            ~Server();
            void handle_aitf_pkt(AITFPacket *);
            void update_rr(unsigned char *, Flow *);

        private:
            FlowPaths *flows;
            bool packet_action();
    };/*}}}*/
}

#endif
