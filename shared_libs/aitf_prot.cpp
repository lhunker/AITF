#include <openssl/rand.h>
#include <math.h>
#include <time.h>
#include "aitf_prot.h"

namespace aitf {
    Flow::Flow() {
        queue<int> ips(6);
        queue<int> hashes(6);
    }

    Flow::AddHop(int ip, int hash) {
        // Using a maximum of six entries in a flow as per AITF whitepaper
        // This mitigates route extension attacks
        if (ips.size() == ips.capacity()) {ips.pop(); hashes.pop();}
        ips.push(ip);
        hashes.push(hash);
    }

    FlowPaths::FlowPaths() {
        // This is a data structure wrapper, essentially
        // Only needs to initialize variables
        vector<Flow> route_ips(10);
        vector<int> pkt_count(10);
        vector<int> pkt_times(10);
    }

    FlowPaths::AddFlow(Flow *flow) {
        // Check if flow already exists in table
        for (int i = 0; i < ip_routes.size(); i++) {
            // TODO: Override flow equality operator
            // If yes, check that time hasn't expired and either reset
            // or increment count
            if (ip_routes[i] == route) {
                if (pkt_times[i] + T < time(NULL)) {
                    ResetCount();
                    return;
                } else {
                    pkt_count[i]++;
                    // TODO: Check attack threshold here
                    return;
                }
            }
        }
        // No resize is necessary as the vector library reallocates as necessary
        route_ips.push_back(route);
        pkt_count.push_back(0);
        pkt_times.push_back(time(NULL));
    }

    FlowPaths::ResetCount(int flow) {
        // Triggered upon packet reception, hence 1 instead of 0
        pkt_count[flow] = 1;
        pkt_time[flow] = time(NULL);
    }

    // Getters and setters
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

    // For initial connections in which we do not have values
    AITFPacket::AITFPacket(unsigned mode:4) {
        mode = mode;

        // Seed random generator and pick random sequence/nonce values
        srand(time(NULL));
        set_seq(rand() % (pow(2, 8)));
        // Using openSSL for characters
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes(nonce, 16);
        Flow flow();
    }

    // Used when responding to connections and the nonce and sequence
    // have already been calculated
    AITFPacket::AITFPacket(unsigned mode:4, unsigned seq:16, char nonce[16]) {
        set_mode(mode);
        set_seq(seq);
        set_nonce(nonce);
        Flow flow();
    }
}
