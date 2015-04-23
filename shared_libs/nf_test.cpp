#include "aitf_prot.h"
#include "aitf_nf.h"

using aitf::AITFPacket;

int main(int argc, char *argv[]) {
    aitf::NFQ nfq;
    nfq.loop();
}

void aitf::NFQ::update_rr(struct iphdr *iph, Flow flow) {
}

void aitf::NFQ::handle_aitf_pkt(aitf::AITFPacket *pkt) {/*{{{*/
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
