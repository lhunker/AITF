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
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

namespace aitf {
    extern struct nfq_handle *nfq_h;
    extern struct nfq_q_handle *nfq_qh;
    extern int nfq_fd;
    
    void nfq_init();
    void nfq_loop();
    void nfq_close();
    static int process_packet(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*) 
}
#endif
