//
// Created by lhunker on 4/23/15.
// 
#ifndef AITF_NFQ_ROUTER_H
#define AITF_NFQ_ROUTER_H

#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/common.h"
#include "filter_line.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <map>

using std::vector;
using std::map;

#define HASH_TIMEOUT 600
#define BLOCK_TIMEOUT 10
#define BLOCK_THRESH 50
#define BLOCK_THRESH_RESET 10

namespace aitf {
    //struct to hold information about a router's endhosts
    struct endhost {
        int ip;    //the host's ip address
        bool legacy;    //true if the host is legacy
    } typedef endhost;

    class nfq_router : public NFQ {
    public:/*{{{*/
        nfq_router(vector<endhost> hostIn, char *);

        ~nfq_router();

        int handlePacket(struct nfq_q_handle*, int, int, unsigned char *, Flow *);

        int handle_aitf_pkt(struct nfq_q_handle *, int, unsigned int, unsigned int, AITFPacket *);/*}}}*/

    private:/*{{{*/
        char *s_ip;
        int ip;
        char *key;

        char *old_key;

        map<unsigned int,int> aitf_block;
        map<unsigned int,int> aitf_block_time;
        map<unsigned int,int> aitf_pkt_count;
        map<unsigned int,int> aitf_pkt_time;

        map<int,int> seq_data;
        map<int,char*> nonce_data;
        vector<filter_line> filters;

        void update_key();

        bool check_filters(Flow *f, char *hash, unsigned dest, unsigned src);

        void escalate(filter_line, Flow*);

        void remove_filter(int);

        void remove_filter(unsigned dest, unsigned src);

        AITFPacket handle_victim_request(AITFPacket *);

        bool to_legacy_host(int ipIn);

        bool addFilter(filter_line f);
        int clear_aitf_conn(struct nfq_q_handle*, int, unsigned int);
        unsigned char *update_pkt(unsigned char *old_payload, Flow *f, int pkt_size, bool);
        vector<endhost> subnet;

    };/*}}}*/
}

#endif //AITF_NFQ_ROUTER_H
