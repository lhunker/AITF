#ifndef AITF_LEGACY_H
#define AITF_LEGACY_H

#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/common.h"
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <map>

#define PKT_THRESHOLD 5
#define PKT_TIMEOUT .5

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

        int handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, unsigned int dest_ip, AITFPacket *pkt);

        int handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload, Flow *flow);

        private:
            FlowPaths *flows;
    };/*}}}*/
}

#endif
