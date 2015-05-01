#include <stdio.h>
#include <math.h>
#include <string.h>
#include <iostream>
#include <openssl/rand.h>
#include "aitf_prot.h"
#include "common.h"

using std::istringstream;

namespace aitf {
    Flow::Flow() {/*{{{*/
        ips = *(new deque<int>(6, 0));
        hashes = *(new deque<char*>(6));
        for (int i = 0; i < 6; i++) {
            hashes[i] = create_str(8);
            strcpy(hashes[i], "00000000");
        }
    }/*}}}*/

    /**
     * Adds a hop to a given flow
     * @param ip
     * @param hash
     */
    void Flow::add_hop(int ip, char *hash) {/*{{{*/
        // Using a maximum of six entries in a flow as per AITF whitepaper
        // This mitigates route extension attacks
        ips.pop_front();
        free(hashes[0]);
        hashes.pop_front();
        ips.push_back(ip);
        hashes[5] = create_str(8);
        memcpy(hashes[5], hash, 8);
    }/*}}}*/

    const bool Flow::operator==(const Flow &f) {/*{{{*/
        for (int i = 0; i < 6; i++) {if (ips.at(i) != f.ips.at(i)) return false;}// || memcmp(hashes.at(i), f.hashes.at(i), 8) != 0) {return false;}}
        return true;
    }/*}}}*/

    void Flow::debugPrint() {
        for (int i = 0; i < 6; i++) {
            printf("%d - ", ips[i]);
        }
        printf("\n");
    }

    /**
     * Populates a flow based off of a continuous data string
     * @param data
     */
    void Flow::populate(unsigned char *data) {/*{{{*/
        // 64 = (32 bits/data entry * (6 ips + 6 hashes)) / 4 bits/char
        // Doubled to get IP/hash pair
        int ip;
        // Split string into 12 x 32 bit chunks and copy into newly-created string variables
        for (int n = 0; n < 72; n += 12) {
            // Convert string version of integers to actual integers
            memcpy(&ip, (char *) data + n, 4);

            ips.pop_front();
            ips.push_back(ip);

            free(hashes[0]);
            hashes.pop_front();
            hashes[5] = create_str(8);
            memcpy(hashes[5], (char *) data + n + 4, 8);
        }
    }/*}}}*/

    /**
     * Converts a flow into a continuous string
     * Pads all unused ips and hashes with 0s
     * @return the string representation of the flow
     */
    char* Flow::serialize() {/*{{{*/
        char *out = create_str(FLOW_SIZE);
        char *tmp = create_str(12);
        for (int i = 0; i < 6; i++) {
            int ip = ips[i];
            memcpy(tmp, &ip, 4);
            sprintf(tmp + 4, "%s", hashes[i]);  //copy hash (8 bytes)
            memcpy(out + 12 * i, tmp, 12);
        }
        free(tmp);
        return out;
    }/*}}}*/

    // Getters and setters/*{{{*/
    void AITFPacket::set_mode(unsigned m) {/*{{{*/
        m = m & 0xF;
        mode = m;
    }/*}}}*/

    void AITFPacket::set_seq(unsigned short seq) {/*{{{*/
        sequence = seq;
    }/*}}}*/

    void AITFPacket::set_nonce(char n[8]) {/*{{{*/
        for (int i = 0; i < 8; i++) { nonce[i] = n[i]; }
    }/*}}}*/

    void AITFPacket::set_nonce(unsigned char n[8]) {/*{{{*/
        for (int i = 0; i < 8; i++) { nonce[i] = n[i]; }
    }/*}}}*/

    unsigned AITFPacket::get_mode() {/*{{{*/
        return mode;
    }/*}}}*/

    unsigned AITFPacket::get_seq() {/*{{{*/
        return sequence;
    }

    Flow::Flow(const Flow &f) {
        ips = deque<int>(f.ips);
        hashes = deque<char *>(6);
        for (int i = 0; i < 6; i++) {
            hashes[i] = create_str(8);
            memcpy(hashes[i], f.hashes[i], 8);
        }
    }

/*}}}*/

    char* AITFPacket::get_nonce() {/*{{{*/
        return nonce;
    }/*}}}*/

    Flow AITFPacket::get_flow() {/*{{{*/
        //TODO does this need to handle the hashes too?
        return flow;
    }/*}}}*/

    void AITFPacket::set_values(unsigned m, unsigned short seq, char *n) {/*{{{*/
        set_mode(m);
        set_seq(seq);
        set_nonce(n);
    }/*}}}*//*}}}*/

    void AITFPacket::set_flow(vector<int> f_ips) {
        for (int i = 0; i < 6; i++) flow.ips[i] = f_ips[i];
    }

    void AITFPacket::set_hashes(deque<char *> h) {

        for (int i = 0; i < 6; i++) {
            if (h[i])
                memcpy(flow.hashes[i], h[i], 8);
            else
                memcpy(flow.hashes[i], "00000000", 8);
        }
    }

    void AITFPacket::populate(char *s) {/*{{{*/
        int i;
        char c[8];
        memcpy(&i, s, sizeof(int));
        set_mode(i);
        memcpy(&i, s + sizeof(int), sizeof(int));
        set_seq(i);
        memcpy(c, s + sizeof(int) * 2, 8);
        set_nonce(c);
        memcpy(&i, s + sizeof(int) * 2 + 8, sizeof(int));
        src_ip = i;
        memcpy(&i, s + sizeof(int) * 3 + 8, sizeof(int));
        dest_ip = i;
        flow.populate((unsigned char*)s + sizeof(int) * 4 + 8);
    }/*}}}*/

    char* AITFPacket::serialize() {/*{{{*/
        char *s = create_str(96);
        memcpy(s, &mode, sizeof(int));
        memcpy(s + sizeof(int), &sequence, sizeof(int));
        memcpy(s + sizeof(int) * 2, &nonce, 8);
        memcpy(s + sizeof(int) * 2 + sizeof(nonce), &src_ip, sizeof(int));
        memcpy(s + sizeof(int) * 3 + sizeof(nonce), &dest_ip, sizeof(int));
        char *fs = flow.serialize();
        memcpy(s + sizeof(int) * 4 + sizeof(nonce), fs, FLOW_SIZE);
        return s;
    }/*}}}*/

    // For initial connections in which we do not have values
    AITFPacket::AITFPacket() {/*{{{*/
    }/*}}}*/

    AITFPacket::AITFPacket(unsigned m) {/*{{{*/
        set_mode(m);

        // Seed random generator and pick random sequence/nonce values
        srand(time(NULL));
        set_seq(fmod(rand(), (pow(2, 16))));
        // Using openSSL for characters
        RAND_load_file("/dev/urandom", 1024);
        unsigned char *buf = create_ustr(8);
        RAND_bytes(buf, 8);
        set_nonce(buf);
        Flow flow;
        free(buf);
    }/*}}}*/

    // Used when responding to connections and the nonce and sequence
    // have already been calculated
    AITFPacket::AITFPacket(unsigned m, unsigned seq, char n[8]) {/*{{{*/
        set_mode(m);
        set_seq(seq);
        set_nonce(n);
        Flow flow;
    }/*}}}*/

    AITFPacket::AITFPacket(unsigned m, unsigned ip, Flow f) {
        flow = f;
        src_ip = ip;
        mode = m;
        set_nonce((char *) "00000000");
        sequence = 5;
    }
}
