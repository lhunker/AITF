//
// Created by lhunker on 4/23/15.
//

#ifndef AITF_NFQ_ROUTER_H
#define AITF_NFQ_ROUTER_H

#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/common.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/rand.h>
#include <map>

using std::vector;
using std::map;

#define HASH_TIMEOUT 600

namespace aitf {
    //struct to hold information about a router's endhosts
    struct endhost {
        int ip;    //the host's ip address
        bool legacy;    //true if the host is legacy
    } typedef endhost;

    class nfq_router : public NFQ {
    public:
        nfq_router(vector<endhost> hostIn, char *);

        ~nfq_router();

        int handlePacket(struct nfq_q_handle*, int, int, unsigned char *, Flow *);

        int handle_aitf_pkt(struct nfq_q_handle*, int, AITFPacket *);

    private:
        char *s_ip;
        int ip;
        char *hash;

        char *old_hash;

        map<int,int> seq_data;
        map<int,char*> nonce_data;
        vector< vector<int> > filters;

        void update_hash();

        bool check_filters(Flow *);

        bool to_legacy_host(int ipIn);

        int clear_aitf_conn(struct nfq_q_handle*, int);
        unsigned char *update_pkt(unsigned char *old_payload, Flow *f, int pkt_size);
        vector<endhost> subnet;

    };
}

#endif //AITF_NFQ_ROUTER_H
