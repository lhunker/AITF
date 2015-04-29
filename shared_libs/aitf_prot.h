#ifndef __AITF_PROT_H
#define __AITF_PROT_H

#include <vector>
#include <deque>

using std::vector;
using std::deque;

namespace aitf {
    // Network protocol modes

    #define AITF_HELO 0
    #define AITF_CONF 1
    #define AITF_ACT 2
    #define AITF_ACK 3
    #define AITF_REQ 4  //request from a vicitim to its gateway

    #define FLOW_SIZE 144
    class Flow {/*{{{*/
    public:
        deque<int> ips;

        Flow();

        void add_hop(int, char *);

        const bool operator==(const Flow &);

        // Used to make a string for storing
        char *serialize();

        // Used to create a Flow from a string
        void populate(unsigned char *);

    private:
        deque<char *> hashes;
    };

    /*}}}*/

    class AITFPacket {/*{{{*/
    public:
        AITFPacket();

        AITFPacket(unsigned);

        AITFPacket(unsigned, unsigned, char[8]);

        unsigned get_mode();

        unsigned get_seq();

        char *get_nonce();

        vector<int> get_flow();

        void set_flow(vector<int>);

        void set_values(unsigned, unsigned short, char *);

        // Used to make a string for storing
        char *serialize();

        // Used when sending over the network
        char *pack();

    private:
        //TODO add dest ip to block?
        unsigned mode;
        unsigned short sequence;
        Flow flow;
        char nonce[8];

        void set_mode(unsigned);

        void set_seq(unsigned short);

        void set_nonce(char[8]);

        void set_nonce(unsigned char[8]);
    };/*}}}*/
}
#endif
