//
// Created by lhunker on 4/23/15.
//

#include "nfq_router.h"

namespace aitf {

    nfq_router::nfq_router(vector<endhost> hostIn, char *str_ip) {/*{{{*/
        s_ip = create_str(15);
        strcpy(s_ip, str_ip);
        struct sockaddr_in s;
        inet_aton(str_ip, &s.sin_addr);
        ip = s.sin_addr.s_addr;

        subnet = vector<endhost>(hostIn);

        old_hash = NULL;
        hash = create_ustr(32);
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes(hash, 32);
    }/*}}}*/

    nfq_router::~nfq_router() {/*{{{*/
        free(s_ip);
        free(hash);
    }/*}}}*/

    /**
     * Updates the hash of this router
     */
    void nfq_router::update_hash() {/*{{{*/
        old_hash = hash;
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes(hash, 32);
    }/*}}}*/

    /**
     * Determine mode of AITF packet and respond, taking appropriate action
     * @param pkt
     */
    int nfq_router::handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, AITFPacket *pkt) {/*{{{*/
        //TODO implement function
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
                return nfq_set_verdict(qh, pkt_id, AITF_DROP_PACKET, 0, NULL);
        }
        return nfq_set_verdict(qh, pkt_id, AITF_ACCEPT_PACKET, 0, NULL);
        // send response packet here
    }/*}}}*/

    /**
     * Adds the flow to a packet
     * @param old_payload the old packet
     * @param f the flow to add
     * @param pkt_size the size of the packet
     * @return the updated packet
     */
    unsigned char *nfq_router::update_pkt(unsigned char *old_payload, Flow *f, int pkt_size) {
        unsigned char *new_payload = create_ustr(pkt_size + 384 + 64);
        for (int i = 0; i < sizeof(struct iphdr); i++) { new_payload[i] = old_payload[i]; }
        // TODO where should we add the 64 '0' characters?
        char *fs = f->serialize();
        strcat((char *) new_payload, fs);
        for (int i = sizeof(struct iphdr); i < pkt_size; i++) {
            *(new_payload + i + strlen(fs)) = *(old_payload + i);
        }
        free(fs);
        return new_payload;
    }

/**
     * Update route record layer as appropriate for network position
     * and replace current packet in kernel
     * @param payload
     * @param flow
     */
    int nfq_router::handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload, Flow *flow) {/*{{{*/
        unsigned int dest_ip = ((struct iphdr*)payload)->daddr;
        unsigned char *new_pkt;
        // If in filters, drop it
        if (check_filters(flow)) {
            return nfq_set_verdict(qh, pkt_id, AITF_DROP_PACKET, 0, NULL);
        // If going to legacy host, discard RR record
        } else if (to_legacy_host(dest_ip)) {
            new_pkt = strip_rr(payload);
        } else if (flow == NULL) {
            flow = new Flow();
            flow->add_hop(ip, hash);
            // Insert a flow in the middle of the IP header and the rest of the packet
            new_pkt = update_pkt(payload, flow, pkt_size);
        // Otherwise I am an intermediary router, so add myself as a hop
        } else {
            flow->add_hop(ip, hash);
            unsigned char *tmp = strip_rr(payload);
            new_pkt = update_pkt(tmp, flow, pkt_size);
            free(tmp);
        }
        // TODO: swap for existing packet
        return nfq_set_verdict(qh, pkt_id, AITF_ACCEPT_PACKET, 0, NULL);
    }/*}}}*/

    /**
     * Determines if the packet is being sent to one of the routers legacy hosts
     * @return true if sent to legacy host in subnet, false otherwise
     */
    bool nfq_router::to_legacy_host(int ipIn) {/*{{{*/
        for (int i = 0; i < subnet.size(); i++) {
            if (subnet[i].ip == ipIn && subnet[i].legacy) {
                return true;
            }
        }
        return false;
    }/*}}}*/

    /**
     * Check if received packet violates a filter
     * @return true if packet should be dropped, false otherwise
     */
    bool nfq_router::check_filters(Flow *flow) {/*{{{*/
        for (int i = 0; i < filters.size(); i++) {
            for (int j = 0; j < flow->ips.size(); j++) {
                if (flow->ips.at(j) != filters[i].at(j)) {break;}
                return true;
            }
        }
        return false;
    }/*}}}*/
}


