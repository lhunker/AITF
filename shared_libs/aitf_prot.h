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
    #define AITF_ACK 2

    class Flow {/*{{{*/
        public:
            deque<int> ips;

            Flow();

        void add_hop(int, unsigned char *);
            const bool operator==(const Flow&);
           // Used to make a string for storing
            char* serialize();
            // Used to create a Flow from a string
            void populate(unsigned char*);
        private:
            deque<unsigned char*> hashes;
    };/*}}}*/

    class AITFPacket {/*{{{*/
        public:
           AITFPacket();
           AITFPacket(unsigned);
           AITFPacket(unsigned,unsigned,char[16]);
           unsigned get_mode();
           unsigned get_seq();
           char* get_nonce();
           void set_values(unsigned,unsigned,char[16]);
           // Used to make a string for storing
           char* serialize();
           // Used when sending over the network
           char* pack();
        private:
            unsigned mode;
            unsigned sequence;
            Flow flow;
            char nonce[16];
            void set_mode(unsigned);
            void set_seq(unsigned);
            void set_nonce(char[16]);
            void set_nonce(unsigned char[16]);
    };/*}}}*/
}
#endif
