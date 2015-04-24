#include "server_aitf.h"

namespace aitf {
    Server::Server() {
        flows = new FlowPaths();
    }

    Server::~Server() {
        delete flows;
    }

    void Server::handle_aitf_pkt(AITFPacket *pkt) {
    }

    void Server::update_rr(unsigned char *payload, Flow *flow) {
        flows->add_flow(*flow);
        unsigned char *new_payload = create_ustr(strlen((char*)payload) - 64 - sizeof(Flow));
        strncpy((char*)new_payload, (char*)payload, sizeof(struct iphdr));
        strcpy((char*)new_payload, (char*)payload[sizeof(struct iphdr) + 64 + sizeof(Flow)]);
        // TODO: reinsert new_payload as packet
    }

    bool Server::check_filters() {
        // Since at an end host, always accept packet
        return false;
    }
}
