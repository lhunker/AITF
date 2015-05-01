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

#define PKT_THRESHOLD 55
#define FLOW_THRESHOLD 150
#define PKT_TIMEOUT 1

using std::map;
namespace aitf {
    class FlowPaths {/*{{{*/
        public:
            FlowPaths();

        void add_flow(Flow, unsigned);

        private:
            int timeout;
            vector<Flow> route_ips;
        vector<vector<unsigned> > src_ips;
        vector<vector<int> > pkt_count;
        vector<vector<int> > pkt_times;
        map<unsigned, int> last_filter;

        void sendFilterRequest(Flow f, int ip);

        void reset_count(int, int);

        void reset_times(int flow);

        bool check_attack_thres_ip(int flow);

        bool check_attack_thres_flow(int flow, int i);
    };/*}}}*/

    class Server : public NFQ {/*{{{*/
        public:
            Server();
            ~Server();

        int handle_aitf_pkt(struct nfq_q_handle *, int, unsigned int, unsigned int, AITFPacket *);

        int handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload, Flow *flow);

        private:

        FlowPaths *flows;
    };/*}}}*/
}

#endif
