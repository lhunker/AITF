#include <openssl/rand.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <sstream>
#include "aitf_prot.h"
#include "common.h"

using std::istringstream;

namespace aitf {
    Flow::Flow() {/*{{{*/
    }/*}}}*/

    /**
     * Adds a hop to a given flow
     * @param ip
     * @param hash
     */
    void Flow::add_hop(int ip, int hash) {/*{{{*/
        // Using a maximum of six entries in a flow as per AITF whitepaper
        // This mitigates route extension attacks
        if (ips.size() == 6) {ips.pop_front(); hashes.pop_front();}
        ips.push_back(ip);
        hashes.push_back(hash);
    }/*}}}*/

    const bool Flow::operator==(const Flow &f) {/*{{{*/
        for (int i = 0; i < 6; i++) {if (ips.at(i) != f.ips.at(i) || hashes.at(i) != f.hashes.at(i)) {return false;}}
        return true;
    }/*}}}*/

    /**
     * Populates a flow based off of a continuous data string
     * @param data
     */
    void Flow::populate(unsigned char *data) {/*{{{*/
        // 64 = (32 bits/data entry * (6 ips + 6 hashes)) / 4 bits/char
        // Doubled to get IP/hash pair
        char *ip = create_str(8);
        char *hash = create_str(8);
        for (int n = 0; n < 32; n += 16) {
            strncpy(ip, (char*)data[n], 8);
            strncpy(hash, (char*)data[n + 8], 8);
            // Convert string version of integers to actual integers
            istringstream sp(ip);
            int i;
            sp >> i;
            ips.push_back(i);
            istringstream sh(hash);
            int h;
            sh >> h;
            hashes.push_back(h);
        }
        free(ip);
        free(hash);
    }/*}}}*/

    /**
     * Converts a flow into a continuous string
     * @return the string
     */
    char* Flow::serialize() {/*{{{*/
        return ""; // TODO
    }/*}}}*/

    FlowPaths::FlowPaths() {/*{{{*/
        // This is a data structure wrapper, essentially
        // Only needs to initialize variables
        vector<Flow> route_ips(10);
        vector<int> pkt_count(10);
        vector<int> pkt_times(10);
        timeout = 5; // TODO: actually set this
    }/*}}}*/

    /**
     * Adds a given flow, or increments the packet count
     * Also resets the packet count when appropriate
     * @param flow
     */
    void FlowPaths::add_flow(Flow flow) {/*{{{*/
        // Check if flow already exists in table
        for (int i = 0; i < route_ips.size(); i++) {
            // If yes, check that time hasn't expired and either reset
            // or increment count
            if (route_ips[i] == flow) {
                if (pkt_times[i] + timeout < time(NULL)) {
                    reset_count(i);
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
    }/*}}}*/

    /**
     * Resets packet count for a given flow index
     * @param flow
     */
    void FlowPaths::reset_count(int flow) {/*{{{*/
        // Triggered upon packet reception, hence 1 instead of 0
        pkt_count[flow] = 1;
        pkt_times[flow] = time(NULL);
    }/*}}}*/

    // Getters and setters/*{{{*/
    void AITFPacket::set_mode(unsigned m) {/*{{{*/
        m = m & 0xF;
        mode = m;
    }/*}}}*/

    void AITFPacket::set_seq(unsigned seq) {/*{{{*/
        seq = seq & 0xFFFF;
        sequence = seq;
    }/*}}}*/

    void AITFPacket::set_nonce(char n[16]) {/*{{{*/
        for (int i = 0; i < 16; i++) {nonce[i] = n[i];}
    }/*}}}*/

    void AITFPacket::set_nonce(unsigned char n[16]) {/*{{{*/
        for (int i = 0; i < 16; i++) {nonce[i] = n[i];}
    }/*}}}*/

    unsigned AITFPacket::get_mode() {/*{{{*/
        return mode;
    }/*}}}*/

    unsigned AITFPacket::get_seq() {/*{{{*/
        return sequence;
    }/*}}}*/

    char* AITFPacket::get_nonce() {/*{{{*/
        return nonce;
    }/*}}}*/

    void AITFPacket::set_values(unsigned m, unsigned seq, char n[16]) {/*{{{*/
        set_mode(m);
        set_seq(seq);
        set_nonce(n);
    }/*}}}*//*}}}*/

    // For initial connections in which we do not have values
    AITFPacket::AITFPacket() {/*{{{*/
    }/*}}}*/

    AITFPacket::AITFPacket(unsigned m) {/*{{{*/
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
    }/*}}}*/

    // Used when responding to connections and the nonce and sequence
    // have already been calculated
    AITFPacket::AITFPacket(unsigned m, unsigned seq, char n[16]) {/*{{{*/
        set_mode(m);
        set_seq(seq);
        set_nonce(n);
        Flow flow;
    }/*}}}*/
}
