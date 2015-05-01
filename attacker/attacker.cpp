#include "attacker.h"

namespace aitf {
    Attacker::Attacker(int c) {
        comply = c;
    }

    void* Attacker::start_func(void *This) {((Attacker *)This)->start(); return NULL;}

    void Attacker::start() {
        printf("IMMA FIRIN MAH LAZOR\n");
        while (1) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            // Hard coded victim, deal with it
            inet_aton("10.4.10.1", &addr.sin_addr);
            // Choose a random port
            srand(time(NULL));
            int port = 5555;
            addr.sin_port = htons(port);
            char *msg = "TROLLLLLLOLOLOLOL";
            int msg_size = strlen(msg);
            if (sendto(sock, msg, msg_size, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
                printf("Failed to send UDP flood message\n");
        }
    }

    void Attacker::fire_lazor() {
        pthread_create(&attack, NULL, Attacker::start_func, this);
    }

    int Attacker::handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, unsigned int src_ip, unsigned int dest_ip, AITFPacket *pkt) {
        switch (pkt->get_mode()) {
            case AITF_CEASE:
                if (comply == AITF_COMPLIANT) {
                    pthread_cancel(attack);
                    printf("Lazorz offline\n");
                } else if (comply == AITF_NONCOMPLIANT) {
                    printf("LEEERRROOOOY JEN-----------\nALL GLORY TO THE HYPNOTOAD\nALL GLORY TO THE HYPNOTOAD\n");
                    return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
                    // Do nothing
                } else if (comply == AITF_SNEAKY) {
                    printf("They see me rollin', they hatin'\n");
                    pthread_cancel(attack);
                    // ..... and start again
                    sleep(15);
                    pthread_create(&attack, NULL, Attacker::start_func, this);
                }
                break;
            case AITF_DISCONNECT:
                printf("You sunk my battleship\n");
                return 0;
                break;
            default:
                break;
        }

        int ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
        if (ret == -1) {
            printf("Failed to set verdict\n");
            return ret;
        }

        char *sock_ip = create_str(20);
        unsigned char bytes[4];
        src_ip = htonl(src_ip);
        bytes[3] = src_ip & 0xFF;
        bytes[2] = (src_ip >> 8) & 0xFF;
        bytes[1] = (src_ip >> 16) & 0xFF;
        bytes[0] = (src_ip >> 24) & 0xFF;
        sprintf(sock_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

        AITFPacket resp(AITF_CEASE_ACK);
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        inet_aton(sock_ip, &addr.sin_addr);
        addr.sin_port = htons(AITF_PORT);
        free(sock_ip);
        char *msg = resp.serialize();
        int msg_size = sizeof(int) * 4 + 8 + FLOW_SIZE;
        if (sendto(sock, msg, msg_size, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
            printf("Failed to send AITF response\n");
        return ret;
    }

    int Attacker::handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload, Flow *flow) {
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
    }
};
