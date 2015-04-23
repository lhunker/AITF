#ifndef __AITF_NF_H
#define __AITF_NF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "aitf_prot.h"

#define MAX_IPS 10

// nullptr emulation
class nullptr_t {/*{{{*/
  public:
    template<class T>
    inline operator T*() const // convertible to any type of null non-member pointer...
    {return 0;}

    template<class C, class T>
    inline operator T C::*() const   // or any type of null member pointer...
    {return 0;}

  private:
    void operator&() const;  // Can't take address of nullptr
} nullptr = {};/*}}}*/

namespace aitf {
    char* create_str(int);

    #define AITF_PORT 40
    class NFQ {/*{{{*/
        public:
            NFQ();
            void loop();
            void close();
        private:
            struct nfq_handle *h;
            struct nfq_q_handle *qh;
            int fd;
            char *ips[MAX_IPS];
            Flow* extract_rr(unsigned char*);
            void handle_aitf_pkt(AITFPacket*);
            void add_rr_and_forward(unsigned char*);
            void remove_rr();
            void update_rr_and_forward(struct iphdr*, Flow);
            bool check_filters();
            static int process_packet(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
    };/*}}}*/
};
#endif
