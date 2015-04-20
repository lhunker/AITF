#include "aitf_nf.h"
#include "aitf_prot.h"

namespace aitf {
    // TODO: This should be a class
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

        // Bind to queue 0 with specified callback function
        qh = nfq_create_queue(h,  0, &process_packet, NULL);
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

    static int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nf_data, void *data) {
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        ph = nfq_get_msg_packet_hdr(nf_data)
        hwph = nfq_get_packet_hw(nf_data);

        id = ntohl(ph->packet_id);
        unsigned char *payload;
        struct iphdr *ip_info = NULL;
        struct tcphdr *tcp_info = NULL;
        struct udphdr *tcp_info = NULL;
        if (nfq_get_payload(nfq_data, &payload)) {
            ip_info = (struct iphdr*)data;
            // TODO: Should add UDP too
            if (ip_info->protocol == IPPROTO_TCP) {
                tcp_info = (struct tcphdr*)(data + sizeof(*ip_info));
            } else if (ip_info->protocol == IPPROTO_UDP) {
                udp_info = (struct udphdr*)(data + sizeof(*ip_info));
            }
        }

        // TODO: Need to ensure this is only called in hosts connected to us
        if (udp_info && ntohs(udp_info->dest) == AITF_PORT) {
            handle_aitf_pkt(); // Need to figure out what to do with this
        } else {
            update_rr();
        }

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); // Or NF_DROP
    }

    void handle_aitf_pkt() {
    }

    void add_rr_layer() {
    }

    void remove_rr() {
    }

    void update_rr() {
        // Outsource to client/server code following this logic
        // If first hop from source, add
        // If last hop to dest and legacy host, remove, otherwise leave intact
        // If host, add to filter table
        // Otherwise, update
    }

    void nfq_loop() {
        char buf[4096] __attribute__ ((aligned));
        int read_count;

        while ((read_count = recv(nfq_fd, buf, sizeof(buf), 0)) && rv >= 0) {
            // This is a system call which takes appropriate action as returned by the callback
            nfq_handle_packet(nfq_h, buf, rv);
        }
    }

    void nfq_close() {
        nfq_destroy_queue(nfq_qh);
        nfq_close(nfq_h);
    }
}
