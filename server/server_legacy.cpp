#include "server_legacy.h"

namespace aitf {
    Server::Server() {
    }

    Server::~Server() {
    }

    void Server::handle_aitf_pkt(AITFPacket *pkt) {
        // Legacy, so do nothing
    }

    void Server::update_rr(unsigned char *payload, Flow *flow) {
        if (extract_rr(payload) != NULL) {
            // TODO: Need to fail here, since upstream router did not do its job
        }
    }

    bool Server::check_filters() {
        // Always acceptable, since no local AITF implementation
        return false;
    }
}
