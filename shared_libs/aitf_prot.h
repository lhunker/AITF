#ifndef __AITF_PROT_H
#define __AITF_PROT_H

// Network protocol modes
#define AITF_HELO 0
#define AITF_CONF 1
#define AITF_ACK 2

#include <vector.h>
#include <queue.h>

class Flow {
    std::queue<int> ips;
    std::queue<int> hashes;
    public:
        Flow();
        void AddHop(int, int);
}

class FlowPaths {
    std::vector<int[6]> route_ips;
    std::vector<int> pkt_count;
    std::vector<int> pkt_times;
    public:
        FlowPaths();
        void AddFlow(int[6]);
    private:
        void reset_count(int);

}

class AITFPacket {
    unsigned mode:4;
    unsigned sequence:16;
    Flow flow;
    unsigned nonce:64;
    public:
       AITFPacket(unsigned:4);
       AITFPacket(unsigned:4,unsigned:16,unsigned:64);
       unsigned get_mode();
       unsigned get_seq();
       unsigned get_nonce();
    private:
        void set_seq(unsigned:16);
        void set_nonce(unsigned:64);
}

#endif
