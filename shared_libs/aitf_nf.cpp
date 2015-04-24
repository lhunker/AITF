#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "aitf_nf.h"
#include "common.h"

// TODO: the +64s aren't accounting for the size field of the AITF layer
// Perhaps strip that out and set the size statically?
namespace aitf {
    NFQ::NFQ() {/*{{{*/
        // Get all of my IP addresses
        struct ifaddrs *ifaddr, *ifa;

        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            exit(EXIT_FAILURE);
        }

        int n = 0;
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL)
                continue;

            char *ip = create_str(4 * 4); // Length of IP address + 1
            ip = inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr);
            ips[n] = ip;
            n++;
        }

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
    }/*}}}*/

    int NFQ::process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nf_data, void *data) {/*{{{*/
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
        struct udphdr *udp_info = NULL;
        Flow flow;
        // Get IP header and data payload
        if (nfq_get_payload(nf_data, &payload)) {
            ip_info = (struct iphdr*)data;
            if (ip_info) {
                // Attempt to extract the RR
                Flow *flow = nf->extract_rr(payload);
                // If one is not present
                if (flow == NULL) {
                    // The addition here strips off the IP header
                    if (ip_info->protocol == IPPROTO_UDP) {
                        udp_info = (struct udphdr*)(payload + sizeof(*ip_info));
                    }
                } else {
                    if (ip_info->protocol == IPPROTO_UDP) {
                        udp_info = (struct udphdr*)(payload + sizeof(*ip_info) + 64 + sizeof(Flow));
                    }
                }
            }
        }

        if ((udp_info && ntohs(udp_info->dest) == AITF_PORT)) { // TODO: Or destination address is one of my addresses
            nf->handle_aitf_pkt(NULL); // TODO: Need to figure out what to do with this
        // If a flow is present
        } else if (strcmp(flow.Serialize(), "") != 0) {
            nf->update_rr(payload, flow);
        }

        int accept = NF_ACCEPT;
        // Check filtering tables for violations
        if (nf->check_filters()) {accept = NF_DROP;}
        return nfq_set_verdict(qh, id, accept, 0, NULL);
    }/*}}}*/

    Flow* NFQ::extract_rr(unsigned char* payload) {/*{{{*/
        // Checks that the first 64 values are zero, which differentiates the
        // shim layer from TCP/UDP or other protocols
        for (int i = 0; i < 64; i++) {if (*(payload + sizeof(struct iphdr) + i) != '\0') return NULL;}
        Flow f;
        f.Populate(payload + sizeof(struct iphdr) + 64);
        return &f;
    }/*}}}*/

    void NFQ::loop() {/*{{{*/
        char buf[4096] __attribute__ ((aligned));
        int read_count;

        while ((read_count = recv(fd, buf, sizeof(buf), 0)) && read_count >= 0) {
            // This is a system call which takes appropriate action as returned by the callback
            nfq_handle_packet(h, buf, read_count);
        }
    }/*}}}*/


    NFQ::~NFQ() {/*{{{*/
        nfq_destroy_queue(qh);
        nfq_close(h);
    }/*}}}*/
}
