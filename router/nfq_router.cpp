//
// Created by lhunker on 4/23/15.
//

#include "nfq_router.h"

namespace aitf {
    void nfq_router::handle_aitf_pkt(AITFPacket *pkt) {/*{{{*/
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
                return;
                break;
        }
    }/*}}}*/

    void nfq_router::update_rr(unsigned char *payload, Flow *flow) {/*{{{*/
        //TODO implement function
        if (check_filters()) {
            //drop packet
        }
        if (flow == NULL) {
            unsigned char* new_payload = create_ustr(strlen((char*)payload) + sizeof(Flow) + 64);
            // flow.AddHop
            // Insert a flow in the middle of the IP header and the rest of the packet
            strncpy((char*)new_payload, (char*)payload, sizeof(struct iphdr));
            strncpy((char*)new_payload, flow->Serialize(), strlen(flow->Serialize()));
            strncpy((char*)new_payload, (char*)payload + sizeof(struct iphdr), strlen((char*)payload + sizeof(struct iphdr)));
            // TODO: swap for existing packet
        // else if destination is in my domain 
        // host doesn't support aitf, strip header
        // else leave intact
        } else {
            // flow.AddHop(me)
        }
    }/*}}}*/

    /**
     * Checks if packet is being filtered against
     * @return true if packet should be dropped, false otherwise
     */
    bool nfq_router::check_filters() {/*{{{*/
        //TODO implement
        return false;
    }/*}}}*/
}


