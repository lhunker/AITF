//
// Created by lhunker on 4/23/15.
//

#include "nfq_router.h"

namespace aitf {

    nfq_router::nfq_router(vector<endhost> hostIn) {/*{{{*/
        subnet = vector<endhost>(hostIn);

        old_hash = NULL;
        hash = create_ustr(64);
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes(hash, 64);
    }/*}}}*/

    nfq_router::~nfq_router() {/*{{{*/
        free(hash);
    }/*}}}*/

    /**
     * Updates the hash of this router
     */
    void nfq_router::update_hash() {/*{{{*/
        old_hash = hash;
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes(hash, 64);
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
     * Update route record layer as appropriate for network position
     * and replace current packet in kernel
     * @param payload
     * @param flow
     */
    int nfq_router::handlePacket(struct nfq_q_handle *qh, int pkt_id, unsigned char *payload, Flow *flow) {/*{{{*/
        // Get my IP address based on egress route
        int dest_ip = ((struct iphdr*)payload)->daddr;
        char *ip_cmd = create_str(150);
        sprintf(ip_cmd, "ip route show to match %d | head -1 | grep -oE '([0-9]{,3}\\.){3}[0-9]' | tr -d '\\n'", dest_ip);
        FILE *ip_call = popen(ip_cmd, "r");
        char *str_ip = create_str(15);
        fread(str_ip, 1, 15, ip_call);
        struct sockaddr_in s;
        inet_aton(str_ip, &s.sin_addr);
        int my_ip = s.sin_addr.s_addr;

        fclose(ip_call);
        free(ip_cmd);

        if (check_filters(flow)) {
            return nfq_set_verdict(qh, pkt_id, AITF_DROP_PACKET, 0, NULL);
        } else if (to_legacy_host(dest_ip)) {
            // TODO strip RR
        } else if (to_aitf_host(dest_ip)) {
            return nfq_set_verdict(qh, pkt_id, AITF_ACCEPT_PACKET, 0, NULL);
        } else if (flow == NULL) {
            unsigned char* new_payload = create_ustr(strlen((char*)payload) + sizeof(Flow) + 64);
            flow->add_hop(my_ip, hash);
            // Insert a flow in the middle of the IP header and the rest of the packet
            strncpy((char*)new_payload, (char*)payload, sizeof(struct iphdr));
            strncpy((char*)new_payload, flow->serialize(), strlen(flow->serialize()));
            strncpy((char*)new_payload, (char*)payload + sizeof(struct iphdr), strlen((char*)payload + sizeof(struct iphdr)));
        } else {
            flow->add_hop(my_ip, hash);
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
     * Determines if the packet is being sent to one of the routers aitf hosts
     * @return true if sent to aitf host in subnet, false otherwise
     */
    bool nfq_router::to_aitf_host(int ipIn) {/*{{{*/
        for (int i = 0; i < subnet.size(); i++) {
            if (subnet[i].ip == ipIn && !subnet[i].legacy) {
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


