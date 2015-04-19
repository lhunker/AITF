#ifndef __AITF_NF_H
#define __AITF_NF_H

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
