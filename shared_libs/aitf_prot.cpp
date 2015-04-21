#include <openssl/rand.h>
#include <math.h>
#include <time.h>
#include "aitf_prot.h"
#include "aitf_nf.h"

namespace aitf {
    Flow::Flow() {
    }

    void Flow::AddHop(int ip, int hash) {
        // Using a maximum of six entries in a flow as per AITF whitepaper
        // This mitigates route extension attacks
        if (ips.size() == 6) {ips.pop(); hashes.pop();}
        ips.push(ip);
        hashes.push(hash);
    }

    FlowPaths::FlowPaths() {
        // This is a data structure wrapper, essentially
        // Only needs to initialize variables
        vector<Flow> route_ips(10);
        vector<int> pkt_count(10);
        vector<int> pkt_times(10);
        timeout = 5; // TODO: actually set this
    }

    void FlowPaths::AddFlow(Flow flow) {
        // Check if flow already exists in table
        for (int i = 0; i < route_ips.size(); i++) {
            // TODO: Override flow equality operator
            // If yes, check that time hasn't expired and either reset
            // or increment count
            if (route_ips[i] == flow) {
                if (pkt_times[i] + timeout < time(NULL)) {
                    ResetCount(i);
                    return;
                } else {
                    pkt_count[i]++;
                    // TODO: Check attack threshold here
                    return;
                }
            }
        }
        // No resize is necessary as the vector library reallocates as necessary
        route_ips.push_back(flow);
        pkt_count.push_back(0);
        pkt_times.push_back(time(NULL));
    }

    void FlowPaths::ResetCount(int flow) {
        // Triggered upon packet reception, hence 1 instead of 0
        pkt_count[flow] = 1;
        pkt_times[flow] = time(NULL);
    }

    // Getters and setters
    // TODO: set bit length for variables on these
    void AITFPacket::set_mode(unsigned m) {
        mode = m;
    }

    void AITFPacket::set_seq(unsigned seq) {
        sequence = seq;
    }

    void AITFPacket::set_nonce(char n[16]) {
        for (int i = 0; i < 16; i++) {nonce[i] = n[i];}
    }

    unsigned AITFPacket::get_mode() {
        return mode;
    }

    unsigned AITFPacket::get_seq() {
        return sequence;
    }

    char* AITFPacket::get_nonce() {
        return nonce;
    }

    // For initial connections in which we do not have values
    AITFPacket::AITFPacket(unsigned m) {
        set_mode(m);

        // Seed random generator and pick random sequence/nonce values
        srand(time(NULL));
        set_seq(fmod(rand(), (pow(2, 8))));
        // Using openSSL for characters
        RAND_load_file("/dev/urandom", 1024);
        char *buf = create_str(16);
        RAND_bytes(buf, 16);
        set_nonce(buf);
        Flow flow;
    }

    // Used when responding to connections and the nonce and sequence
    // have already been calculated
    AITFPacket::AITFPacket(unsigned m, unsigned seq, char n[16]) {
        set_mode(m);
        set_seq(seq);
        set_nonce(n);
        Flow flow;
    }
}
