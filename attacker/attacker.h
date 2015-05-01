#include <iostream>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "../shared_libs/aitf_nf.h"
#include "../shared_libs/aitf_prot.h"
#include "../shared_libs/common.h"

#define AITF_CEASE 5
#define AITF_CEASE_ACK 6
#define AITF_DISCONNECT 7

#define AITF_COMPLIANT 0 
#define AITF_NONCOMPLIANT 1
#define AITF_SNEAKY 2

namespace aitf {
    class Attacker : public NFQ  {
        public:

            Attacker(int mode);

            static void* start_func(void *This);

            void start();

            void fire_lazor();

            int handle_aitf_pkt(struct nfq_q_handle *, int, unsigned int, unsigned int, AITFPacket *pkt);

            int handlePacket(struct nfq_q_handle*, int, int, unsigned char *, Flow *);

            int comply;

        private:
            pthread_t attack;
    };
};
