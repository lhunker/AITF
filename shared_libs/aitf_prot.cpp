#include <openssl/rand.h>
#include <math.h>
#include <time.h>
#include "aitf_prot.h"

using std::find;
using std::vector;
using std::queue;

namespace aitf {
    Flow::Flow() {
        queue<int> ips(6);
        queue<int> hashes(6);
    }

    Flow::AddHop(int ip, int hash) {
        if (ips.size() == ips.capacity()) {ips.pop(); hashes.pop();}
        ips.push(ip);
        hashes.push(hash);
    }

    FlowPaths::FlowPaths() {
        vector<Flow> route_ips(10);
        vector<int> pkt_count(10);
        vector<int> pkt_times(10);
    }

    FlowPaths::AddFlow(Flow *flow) {
        // No resize is necessary as the vector library reallocates as necessary
        for (int i = 0; i < ip_routes.size(); i++) {
            // TODO: Override flow equality operator
            if (ip_routes[i] == route) {
                if (pkt_times[i] + T < time(NULL)) {
                    ResetCount();
                } else {
                    pkt_count[i]++;
                    // TODO: Check attack here
                }
            }
        }
        route_ips.push_back(route);
        pkt_count.push_back(0);
        pkt_times.push_back(time(NULL));
    }

    FlowPaths::ResetCount(int flow) {
        pkt_count[flow] = 1;
        pkt_time[flow] = time(NULL);
    }

    AITFPacket::set_mode(unsigned mode::4) {
        mode = mode;
    }

    AITFPacket::set_seq(unsigned seq::4) {
        seq = seq;
    }

    AITFPacket::set_nonce(unsigned nonce::4) {
        nonce = nonce;
    }

    AITFPacket::get_mode() {
        return mode;
    }

    AITFPacket::get_seq() {
        return seq;
    }

    AITFPacket::get_nonce() {
        return nonce;
    }

    AITFPacket::AITFPacket(unsigned mode:4) {
        mode = mode;
        srand(time(NULL));
        set_seq(rand() % (pow(2, 8)));
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes(nonce, 16);
        Flow flow();
    }

    AITFPacket::AITFPacket(unsigned mode:4, unsigned seq:16, char nonce[16]) {
        set_mode(mode);
        set_seq(seq);
        set_nonce(nonce);
        Flow flow();
    }
}
