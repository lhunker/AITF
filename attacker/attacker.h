#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/common.h"

namespace aitf {
    class Attacker : public NFQ  {
        public:
            Attacker();

            void fire_lazor();

            void start_attack();

            void stop_attack();
            
            void sleep_attack();

            int handle_aitf_pkt(struct nfq_q_handle *, int, unsigned int, unsigned int, AITFPacket *pkt);

            int handlePacket(struct nfq_q_handle*, int, int, unsigned char *, Flow *);
    };
};
