#include <openssl/rand.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include "aitf_prot.h"

namespace aitf {
    unsigned char* create_ustr(int l) {
        unsigned char *s = (unsigned char*)malloc(sizeof(char) * (l + 1));
        memset(s, '\0', l + 1);
        return s;
    }

    Flow::Flow() {
    }

    void Flow::AddHop(int ip, int hash) {
        // Using a maximum of six entries in a flow as per AITF whitepaper
        // This mitigates route extension attacks
        if (ips.size() == 6) {ips.pop_front(); hashes.pop_front();}
        ips.push_back(ip);
        hashes.push_back(hash);
    }

    const bool Flow::operator==(const Flow &f) {
        for (int i = 0; i < 6; i++) {if (ips.at(i) != f.ips.at(i) || hashes.at(i) != f.hashes.at(i)) {return false;}}
        return true;
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
    void AITFPacket::set_mode(unsigned m) {
        m = m & 0xF;
        mode = m;
    }

    void AITFPacket::set_seq(unsigned seq) {
        seq = seq & 0xFFFF;
        sequence = seq;
    }

    void AITFPacket::set_nonce(char n[16]) {
        for (int i = 0; i < 16; i++) {nonce[i] = n[i];}
    }

    void AITFPacket::set_nonce(unsigned char n[16]) {
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

    void AITFPacket::set_values(unsigned m, unsigned seq, char n[16]) {
        set_mode(m);
        set_seq(seq);
        set_nonce(n);
    }

    // For initial connections in which we do not have values
    AITFPacket::AITFPacket() {
    }

    AITFPacket::AITFPacket(unsigned m) {
        set_mode(m);

        // Seed random generator and pick random sequence/nonce values
        srand(time(NULL));
        set_seq(fmod(rand(), (pow(2, 8))));
        // Using openSSL for characters
        RAND_load_file("/dev/urandom", 1024);
        unsigned char *buf = create_ustr(16);
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
