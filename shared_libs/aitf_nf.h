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

#define BUF_SIZE 4096
#define MAX_IPS 10

namespace aitf {
#define AITF_PORT 40
    class NFQ {/*{{{*/
    public:
        NFQ();
        ~NFQ();
        void loop();
        void close();

    private:
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        int fd;
        int ips_long[MAX_IPS];
        char *ips[MAX_IPS];
    protected:
        Flow *extract_rr(unsigned char *);

        virtual int handle_aitf_pkt(struct nfq_q_handle *, int, unsigned int, unsigned int,
                                    AITFPacket *) = 0;  //pure virtual
        virtual int handlePacket(struct nfq_q_handle*, int, int, unsigned char *, Flow *) = 0;
        static int process_packet(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *);
        unsigned char* strip_rr(unsigned char *, int);
    };/*}}}*/
};
#endif
