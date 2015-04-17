#include <openssl/rand.h>
#include <math.h>
#include <time.h>
#include "aitf_prot.h"

using namespace std;

namespace aitf {
    Flow::Flow() {
        std::queue<int> ips(6);
        std::queue<int> hashes(6);
    }

    Flow::AddHop(int ip, int hash) {
        if (ips.size() == ips.capacity()) {ips.pop(); hashes.pop();}
        ips.push(ip);
        hashes.push(hash);
    }

    FlowPaths::FlowPaths() {
        std::vector<int[6]> route_ips(10);
        std::vector<int> pkt_count(10);
        std::vector<int> pkt_times(10);
    }

    FlowPaths::AddFlow(int[6] route) {
        if (route_ips.size() == route_ips.capacity()) {
            int cap = route_ips.capacity();
            route_ips.resize(cap + 10);
            pkt_count.resize(cap + 10);
            pkt_times.resize(cap + 10);
        }
        route_ips.push_back(route);
        pkt_count.push_back(0);
        pkt_times.push_back(time(NULL));
    }

    FlowPaths::ResetCount() {
        for (i = 0; i < pkt_count.capacity(); i++) {pkt_count[i] = 0; pkt_time[i] = time(NULL);}
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

    AITFPacket::AITFPacket(unsigned mode::4) {
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
