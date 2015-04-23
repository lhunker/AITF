#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "aitf_nf.h"
#include "aitf_prot.h"
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

    bool NFQ::check_filters() {/*{{{*/
        // TODO: write this
        return true;
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
                if (flow == nullptr) {
                    // The addition here strips off the IP header
                    if (ip_info->protocol == IPPROTO_UDP) {
                        udp_info = (struct udphdr*)(payload + sizeof(*ip_info));
                    }
                } else {
                    // TODO: skip over flow and get header in case AITF packet with RR
                }
            }
        }

        if ((udp_info && ntohs(udp_info->dest) == AITF_PORT)) { // TODO: Or destination address is one of my addresses
            nf->handle_aitf_pkt(nullptr); // TODO: Need to figure out what to do with this
        // If a flow is present
        } else if (strcmp(flow.Serialize(), "") != 0) {
            nf->update_rr_and_forward(ip_info, flow);
        // TODO: If destination in my subnet and legacy, remove rr
        // Otherwise add route record and forward packet
        } else {
            nf->add_rr_and_forward(payload);
        }

        int accept = NF_ACCEPT;
        // Check filtering tables for violations
        if (nf->check_filters()) {accept = NF_DROP;}
        return nfq_set_verdict(qh, id, accept, 0, NULL);
    }/*}}}*/

    void NFQ::handle_aitf_pkt(aitf::AITFPacket *pkt) {/*{{{*/
        AITFPacket resp;
        switch (pkt->get_mode()) {
            // TODO: We may need another action definition since I do not currently see
            // a way to differentiate between sending/receiving the CONF, which should be
            // used to determine when to take an action on a filter request
            case AITF_HELO:
                // If received the first stage, send back sequence +1 and same nonce
                resp.set_values(AITF_CONF, pkt->get_seq() + 1, pkt->get_nonce());
                break;
            case AITF_CONF:
                // If received the second stage, send back sequence +1 and same nonce
                resp.set_values(pkt->get_mode(), pkt->get_seq() + 1, pkt->get_nonce());
                // TODO: Take action here
                break;
            case AITF_ACK:
                // Request/action should have been taken
                break;
            default:
                return;
                break;
        }
    }/*}}}*/

Flow* NFQ::extract_rr(unsigned char* payload) {/*{{{*/
    // Checks that the first 64 values are zero, which differentiates the
    // shim layer from TCP/UDP or other protocols
    for (int i = 0; i < 64; i++) {if (*(payload + sizeof(struct iphdr) + i) != '\0') return nullptr;}
    Flow f;
    f.Populate(payload + sizeof(struct iphdr) + 64);
    return &f;
}/*}}}*/

    /* TODO:
      * Okay, so the RR stuff (after talking to the guys here at NetOps)
      * should be inserted between the IP header and the TCP header.
      * So it appears the tcp/udp stuff is a subset of the IP header, meaning
      * we need to drop the existing ip header and recreate it using our
      * custom AITFPacket class then append the tcp/udp header
      * Other protocol support, maybe ICMP? Or do we just forward those straight on?
    */
    void NFQ::add_rr_and_forward(unsigned char *payload) {/*{{{*/
        unsigned char* new_payload = create_ustr(strlen((char*)payload) + sizeof(AITFPacket));
        Flow f;
        // TODO: f.AddHop()
        // Insert a flow in the middle of the IP header and the rest of the packet
        strncpy((char*)new_payload, (char*)payload, sizeof(struct iphdr));
        strncpy((char*)new_payload, f.Serialize(), strlen(f.Serialize()));
        strncpy((char*)new_payload, (char*)payload + sizeof(struct iphdr), strlen((char*)payload + sizeof(struct iphdr)));
        // TODO: swap for existing packet
    }/*}}}*/

    void NFQ::remove_rr() {/*{{{*/
        // TODO
    }/*}}}*/

    void NFQ::update_rr_and_forward(struct iphdr *iph, Flow flow) {/*{{{*/
        // TODO: Outsource to client/server code following this logic - taken care of?
        // If first hop from source, add
        // If last hop to dest and legacy host, remove, otherwise leave intact
        // If host, add to filter table
        // Otherwise, update
    }/*}}}*/

    void NFQ::loop() {/*{{{*/
        char buf[4096] __attribute__ ((aligned));
        int read_count;

        while ((read_count = recv(fd, buf, sizeof(buf), 0)) && read_count >= 0) {
            // This is a system call which takes appropriate action as returned by the callback
            nfq_handle_packet(h, buf, read_count);
        }
    }/*}}}*/

    void NFQ::close() {/*{{{*/
        nfq_destroy_queue(qh);
        nfq_close(h);
    }/*}}}*/
}
