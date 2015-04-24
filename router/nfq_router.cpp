//
// Created by lhunker on 4/23/15.
//

#include "nfq_router.h"

namespace aitf {

    nfq_router::nfq_router() {
        //TODO setup endhost list
    }

    nfq_router::~nfq_router() {

    }

    /**
     * Determine mode of AITF packet and respond, taking appropriate action
     * @param pkt
     */
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
        // send response packet here
    }/*}}}*/

    /**
     * Update route record layer as appropriate for network position
     * and replace current packet in kernel
     * @param payload
     * @param flow
     */
    void nfq_router::update_rr(unsigned char *payload, Flow *flow) {/*{{{*/
        //TODO implement function
        if (check_filters()) {
            //drop packet
        } else if (to_legacy_host()) {
            extract_rr(payload);
        }
        else if (flow == NULL) {
            unsigned char* new_payload = create_ustr(strlen((char*)payload) + sizeof(Flow) + 64);
            // flow.AddHop
            // Insert a flow in the middle of the IP header and the rest of the packet
            strncpy((char*)new_payload, (char*)payload, sizeof(struct iphdr));
            strncpy((char*)new_payload, flow->Serialize(), strlen(flow->Serialize()));
            strncpy((char*)new_payload, (char*)payload + sizeof(struct iphdr), strlen((char*)payload + sizeof(struct iphdr)));
            // TODO: swap for existing packet
        // else if destination is in my domain 
            // host doesn't support aitf, strip rr
            // else leave intact and forward packet
        } else {
            // flow.AddHop(me)
        }
    }/*}}}*/

    /**
     * Determines if the packet is being sent to one of the routers legacy hosts
     * @return true if sent to legacy host, false otherwise
     */
    bool nfq_router::to_legacy_host() {
        //TODO implement (probably needs a parameter)
        return false;
    }

    /**
     * Check if received packet violates a filter
     * @return true if packet should be dropped, false otherwise
     */
    bool nfq_router::check_filters() {/*{{{*/
        //TODO implement
        return false;
    }/*}}}*/
}


