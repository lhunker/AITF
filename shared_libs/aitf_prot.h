#ifndef __AITF_PROT_H
#define __AITF_PROT_H


#include <vector.h>
#include <queue.h>

using std::vector;
using std::queue;

namespace aitf {
    // Network protocol modes
    #define AITF_HELO 0
    #define AITF_CONF 1
    #define AITF_ACK 2

    class Flow {
        public:
            Flow();
            void AddHop(int, int);
        private:
            queue<int> ips;
            queue<int> hashes;
    }

    class FlowPaths {
        public:
            FlowPaths();
            void AddFlow(Flow);
        private:
            vector<Flow> route_ips;
            vector<int> pkt_count;
            vector<int> pkt_times;
            void ResetCount();

    }

    class AITFPacket {
        public:
           AITFPacket(unsigned:4);
           AITFPacket(unsigned:4,unsigned:16,unsigned:64);
           unsigned get_mode();
           unsigned get_seq();
           unsigned get_nonce();
        private:
            unsigned mode:4;
            unsigned sequence:16;
            Flow flow;
            char nonce[16];
            void set_mode(unsigned:4);
            void set_seq(unsigned:16);
            void set_nonce(char[16]);
    }
}
#endif
