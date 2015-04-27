#include <stdio.h>
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
            ips_long[n] = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
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

    /**
     * Processes packets received by NFQUEUE
     * @param qh
     * @param nfmsg
     * @param nf_data
     * @param data
     * @return integer from nfq_set_verdict on whether to accept a packet
     */
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
        Flow *flow;
        int dest_port = -1;
        // Get IP header and data payload
        if (nfq_get_payload(nf_data, &payload)) {
            ip_info = (struct iphdr*)data;
            if (ip_info) {
                //for (int i = 0; i < ip_info->tot_len; i++) printf("%c", payload[i]);
                // Attempt to extract the RR
                flow = nf->extract_rr(payload);
                // If one is not present
                if (flow == NULL) {
                    // The addition here strips off the IP header
                    if (ip_info->protocol == IPPROTO_UDP) {
                        udp_info = (struct udphdr*)(payload + sizeof(*ip_info));
                        dest_port = ntohs(udp_info->dest);
                    }
                } else {
                    if (ip_info->protocol == IPPROTO_UDP) {
                        udp_info = (struct udphdr*)(payload + sizeof(*ip_info) + 64 + sizeof(Flow));
                        dest_port = ntohs(udp_info->dest);
                    }
                }
            }
        }

        //have subclass handle packet acceptance
        if ((udp_info != NULL && dest_port == AITF_PORT)) { // TODO: Or destination address is one of my addresses
            return nf->handle_aitf_pkt(qh, id, NULL); // TODO: Need to figure out what to do with this
        // If a flow is present
        } else {
            return nf->handlePacket(qh, id, payload, flow);
        }
    }/*}}}*/

    /**
     * Extracts flow from packet contents
     * @param payload
     * @return flow contained in packet, or NULL if none
     */
    Flow* NFQ::extract_rr(unsigned char* payload) {/*{{{*/
        // Checks that the first 64 values are zero, which differentiates the
        // shim layer from TCP/UDP or other protocols
        for (int i = 0; i < 64; i++) {if (*(payload + sizeof(struct iphdr) + i) != '\0') return NULL;}
        Flow *f = new Flow();
        f->populate(payload + sizeof(struct iphdr) + 64);
        return f;
    }/*}}}*/

    /**
     * Returns the packet with RR data removed
     * @param payload
     * @return Packet minus route record
     */
    unsigned char* NFQ::strip_rr(unsigned char *payload) {/*{{{*/
        // If no RR data
        if (extract_rr(payload) == NULL) {return payload;}
        // Get new packet size, adding size of IP header to length of payload remaining after
        // ip header and flow
        int size = sizeof(struct iphdr) + strlen((char*)payload + sizeof(struct iphdr) + 64 + sizeof(Flow));
        unsigned char *new_payload = create_ustr(size);
        strncat((char*)new_payload, (char*)payload, sizeof(struct iphdr));
        strcat((char*)new_payload, (char*)&payload + sizeof(struct iphdr) + 64 + sizeof(Flow));
        return new_payload;
    }/*}}}*/

    /**
     * Main loop in which packets sent to NFQUEUE are handled
     */
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

    void NFQ::close() {/*{{{*/

    }/*}}}*/
}
