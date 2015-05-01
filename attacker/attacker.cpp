#include "attacker.h"

namespace aitf {
    Attacker::Attacker() {
    }

    void Attacker::fire_lazor() {
    }

    void Attacker::start_attack() {
    }

    void Attacker::stop_attack() {
    }

    void Attacker::sleep_attack() {
    }

    int Attacker::handle_aitf_pkt(struct nfq_q_handle *, int, unsigned int, unsigned int, AITFPacket *pkt) {
        return 0;
    }

    int Attacker::handlePacket(struct nfq_q_handle*, int, int, unsigned char *, Flow *) {
        return 0;
    }
};
