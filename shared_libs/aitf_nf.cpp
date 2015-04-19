#include "aitf_nf.h"

namespace aitf {
    void nfq_init() {
        // Open library handle
        h = nfq_open();
        if (!h) {
            fprintf(stderr, "error during nfq_open()\n");
            exit(1);
        }

        // Set nfnetlink queue as queue handler for AF_INET packets
        if (nfq_bind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "error during nfq_bind_pf()\n");
            exit(1);
        }

        // Bind to queue 0
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
            fprintf(stderr, "error during nfq_create_queue()\n");
            exit(1);
        }

        // Setting mode to copy the whole packet
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
            fprintf(stderr, "can't set packet_copy mode\n");
            exit(1);
        }

        // Get file descriptor for this queue
        fd = nfq_fd(h);

        nfq_set_queue_maxlen(qh, 3200);
    }

    void nfq_handle_pkt(struct nfq_handle*, char *buf, int len) {
    }

    void nfq_loop() {
        char buf[4096] __attribute__ ((aligned));
        int read_count;

        while ((read_count = recv(nfq_fd, buf, sizeof(buf), 0)) && rv >= 0) {
            nfq_handle_pkt(nfq_h, buf, rv);
        }
    }

    void nfq_close() {
        nfq_destroy_queue(nfq_qh);
        nfq_close(nfq_h);
    }
}
