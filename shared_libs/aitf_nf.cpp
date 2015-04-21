#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "aitf_nf.h"
#include "aitf_prot.h"

namespace aitf {
    char* create_str(int l) {
        char *s = (char*)malloc(sizeof(char) * (l + 1));
        memset(s, '\0', l + 1);
        return s;
    }

    // It should have a variable containing my IP addresses - see http://man7.org/linux/man-pages/man3/getifaddrs.3.html
    NFQ::NFQ() {
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
        qh = nfq_create_queue(h, 0, &aitf::NFQ::process_packet, this);
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

        // Set maximum length of the queue (packet buffer) - seems to arbitrary?
        nfq_set_queue_maxlen(qh, 3200);
    }

    int NFQ::process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nf_data, void *data) {
        NFQ *nf = (NFQ*)data;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        ph = nfq_get_msg_packet_hdr(nf_data);
        hwph = nfq_get_packet_hw(nf_data);

        // Get packet ID and headers (protocol-appropriate)
        int id = ntohl(ph->packet_id);
        printf("Got packet with id %d\n", id);
        unsigned char *payload;
        struct iphdr *ip_info = NULL;
        struct tcphdr *tcp_info = NULL;
        struct udphdr *udp_info = NULL;
        if (nfq_get_payload(nf_data, &payload)) {
            ip_info = (struct iphdr*)data;
            if (ip_info) {
                // The addition here strips off the IP header
                if (ip_info->protocol == IPPROTO_TCP) {
                    tcp_info = (struct tcphdr*)(payload + sizeof(*ip_info));
                } else if (ip_info->protocol == IPPROTO_UDP) {
                    udp_info = (struct udphdr*)(payload + sizeof(*ip_info));
                }
            }
        }

        // Get hops from me to destination to determine if host is in my subnet
        // or destination is me
        // Hops start at -1 to account for first line of traceroute
        int hops = -1;
        struct in_addr ip_addr;
        ip_addr.s_addr = ip_info->daddr;
        char *ip = inet_ntoa(ip_addr);
        char *hop_cmd = create_str(strlen(ip) + 20);
        sprintf(hop_cmd, "traceroute %s", ip);
        FILE *pipe = popen(hop_cmd, "r");
        if (pipe) {
            char *buffer = create_str(1000);
            fgets(buffer, 1000, pipe);
            pclose(pipe);
            for (int i = 0; i < 1000; i++) {
                if (buffer[i] == '\0') {break;}
                else if (buffer[i] == '\n') {hops++;}
            }

        }

        // If one hop away, then this AITF packet may need to be intercepted by us
        // as the gateway
        if ((udp_info && ntohs(udp_info->dest) == AITF_PORT && hops == 1)) { // TODO: Or destination address is one of my addresses - fixed with hops and traceroute?
            nf->handle_aitf_pkt(); // TODO: Need to figure out what to do with this
        } else {
            nf->update_rr();
        }

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); // TODO: parse to determine if NF_DROP
    }

    void NFQ::handle_aitf_pkt() {
    }

    void NFQ::add_rr_layer() {
    }

    void NFQ::remove_rr() {
    }

    void NFQ::update_rr() {
        // TODO: Outsource to client/server code following this logic - taken care of?
        // If first hop from source, add
        // If last hop to dest and legacy host, remove, otherwise leave intact
        // If host, add to filter table
        // Otherwise, update
    }

    void NFQ::loop() {
        char buf[4096] __attribute__ ((aligned));
        int read_count;

        while ((read_count = recv(fd, buf, sizeof(buf), 0)) && read_count >= 0) {
            // This is a system call which takes appropriate action as returned by the callback
            nfq_handle_packet(h, buf, read_count);
        }
    }

    void NFQ::close() {
        nfq_destroy_queue(qh);
        nfq_close(h);
    }
}
