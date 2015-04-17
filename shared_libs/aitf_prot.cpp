#include "aitf_prot.h"

Flow::Flow() {
    std::queue<int> ips(6);
    std::queue<int> hashes(6);
}

Flow::AddHop(int ip, int hash) {
    if (ips.size() == ips.capacity()) {ips.pop(); hashes.pop();}
    ips.push(ip);
    hashes.push(hash);
}
