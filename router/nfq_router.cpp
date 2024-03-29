//
// Created by lhunker on 4/23/15.
//

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "nfq_router.h"
#include "checksum.h"

namespace aitf {

    nfq_router::nfq_router(vector<endhost> hostIn, char *str_ip) {/*{{{*/
        s_ip = create_str(15);
        strcpy(s_ip, str_ip);
        unsigned int c1, c2, c3, c4;
        sscanf(s_ip, "%d.%d.%d.%d", &c1, &c2, &c3, &c4);
        ip = (unsigned int) c4 + c3 * 256 + c2 * 256 * 256 + c1 * 256 * 256 * 256;

        subnet = vector<endhost>(hostIn);

        old_key = create_str(32);
        key = create_str(32);
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes((unsigned char *) key, 32);
    }

    /*}}}*/

    nfq_router::~nfq_router() {/*{{{*/
        free(s_ip);
        free(key);
        free(old_key);
    }/*}}}*/

    /**
     * Updates the hash of this router
     */
    void nfq_router::update_key() {/*{{{*/
        strcpy(old_key, key);
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes((unsigned char *) key, 32);
    }/*}}}*/

    /**
     * Removes sequence data and drops current packet
     * @param qh
     * @param pkt_id
     * @return nfq set verdict result
     */
    int nfq_router::clear_aitf_conn(struct nfq_q_handle *qh, int pkt_id, unsigned int ip) {/*{{{*/
        if (aitf_pkt_count.count(ip))
            aitf_pkt_count[ip]++;
        else {
            aitf_pkt_count[ip] = 1;
            aitf_pkt_time[ip] = time(NULL);
        }

        if (aitf_pkt_count[ip] > BLOCK_THRESH) {
            aitf_block[ip] = 1;
            aitf_block_time[ip] = time(NULL);
        } else if ((time(NULL) - aitf_pkt_time[ip]) > BLOCK_THRESH_RESET) {
            aitf_block[ip] = 0;
            aitf_pkt_time[ip] = time(NULL);
        }
        free(nonce_data[pkt_id]);
        int ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
        if (ret == -1) printf("Failed to set verdict!\n");
        return ret;
    }/*}}}*/

    /**
     * Processes a victim's AITF request and sends it to the appropriate gateway
     * @param ip the destination being bloack (or 0 if unknown)
     * @param pkt the aitf request packet from the victim
     */
    AITFPacket nfq_router::handle_victim_request(AITFPacket *pkt) {/*{{{*/
        filter_line filt(pkt->getDest_ip(), pkt->get_flow(), true, pkt->getSrc_ip());
        for (int i = 0; i < 6; i++) {
            if (pkt->flow.ips[i] != 0) {
                filt.last_gw = pkt->flow.ips[i];
                break;
            }
        }

        unsigned short seq;
        char nonce[8];
        RAND_bytes((unsigned char *) &seq, 2);
        RAND_bytes((unsigned char *) nonce, 8);
        AITFPacket req(AITF_HELO, seq, nonce);
        if (addFilter(filt)) {
            req.dest_ip = 0;
            req.src_ip = 0;
        } else {


            req.dest_ip = pkt->dest_ip;
            req.src_ip = pkt->src_ip;
            seq_data[pkt->dest_ip] = seq;
        }
        //TODO setup adding flow to packet - pretty sure this is done because other things work
        // but don't know where


        return req;
    }/*}}}*/

/**
     * Determine mode of AITF packet and respond, taking appropriate action
     * @param pkt
     */
    int nfq_router::handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, unsigned int src_ip, unsigned int dest_ip,
                                    AITFPacket *pkt) {/*{{{*/
        if (aitf_block.count(dest_ip)) {
            // If this address has been blocked, drop packet
            if (aitf_block[dest_ip]) {
                if ((time(NULL) - aitf_block_time[dest_ip]) > BLOCK_TIMEOUT) aitf_block[dest_ip] = 0;
                else {
                    int ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
                    if (ret == -1) printf("Failed to set packet verdict\n");
                    return ret;
                }
            }
        } else {
            aitf_block[dest_ip] = 0;
        }

        AITFPacket cease(5); //AITF_CEASE
        char *sock_ip;
        unsigned char bytes[4];
        int sock;
        struct sockaddr_in addr;
        char *msg;
        int msg_size;

        AITFPacket resp;
        int ret;
        resp.dest_ip = pkt->getDest_ip();
        resp.src_ip = pkt->src_ip;
        Flow f = pkt->get_flow();
        unsigned char *hash;
        unsigned char *s_d;
        int request_dest_ip = 0;
        filter_line filt;
        bool legacy;
        bool s;
        //If not intended for me, forward
        bool mine = (htonl(ip) == dest_ip);
        for (int i = 0; i < subnet.size(); i++) {
            if (subnet[i].ip == dest_ip) {
                mine = true;
            }
        }
        if (!mine) {
            ret = nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
            if (ret == -1) printf("Failed to set verdict\n");
            return ret;
        } else {
            printf("My precious...\n");
            printf("Got AITF control message %d from %u\n", pkt->get_mode(), src_ip);
        }


        switch (pkt->get_mode()) {
            case AITF_HELO:

                // If received the first stage, send back sequence +1 and same nonce
                s_d = create_ustr(15);
                sprintf((char *) s_d, "%d\n", dest_ip);
                hash = HMAC(EVP_md5(), key, strlen(key), s_d, strlen((char *) s_d), NULL, NULL);
                for (int i = 0; i < 6; i++) {
                    if (f.ips[i] == ip && memcmp(f.hashes[i], hash, 8) != 0)
                        clear_aitf_conn(qh, pkt_id, pkt->getDest_ip());
                }

                seq_data[pkt->dest_ip] = pkt->get_seq();
                nonce_data[pkt->dest_ip] = create_str(8);
                char nonce[8];
                RAND_bytes((unsigned char *) nonce, 8);
                memcpy(nonce_data[pkt->dest_ip], nonce, 8);
                request_dest_ip = pkt->dest_ip;
                resp.set_values(AITF_CONF, pkt->get_seq() + 1, nonce);
                free(s_d);
                break;
            case AITF_CONF:
                // Validate sequence and nonce
//                if (seq_data[pkt->dest_ip] != (pkt->get_seq() - 1)) {
//                    return clear_aitf_conn(qh, pkt_id, pkt->getDest_ip());
//                }
                // If received the second stage, send back sequence +1 and same nonce
                resp.set_values(AITF_ACT, pkt->get_seq() + 1, pkt->get_nonce());

                request_dest_ip = htonl(src_ip);
                break;
            case AITF_ACT:
                // Validate sequence and nonce
                if (seq_data[pkt->dest_ip] != (pkt->get_seq() - 2) ||
                        memcmp(nonce_data[pkt->dest_ip], pkt->get_nonce(), 8) != 0) {
                    return clear_aitf_conn(qh, pkt_id, pkt->dest_ip);
                }
                // If receiving a third stage packet, add filter
                request_dest_ip = htonl(src_ip);
                resp.set_values(AITF_ACK, pkt->get_seq() + 1, pkt->get_nonce());
                legacy = to_legacy_host(htonl(pkt->getSrc_ip()));
                s = false;
                for (int j = 0; j < subnet.size(); j++) {
                    if (pkt->getDest_ip() == htonl(subnet[j].ip)) {
                        s = true;
                    }
                }
                filt.setIps(pkt->getDest_ip(), pkt->getSrc_ip(), !legacy && s);
                addFilter(filt);

                if (!legacy) {
                    // Send cease request to attacker
                    sock_ip = create_str(20);
                    bytes[3] = pkt->src_ip & 0xFF;
                    bytes[2] = (pkt->src_ip >> 8) & 0xFF;
                    bytes[1] = (pkt->src_ip >> 16) & 0xFF;
                    bytes[0] = (pkt->src_ip >> 24) & 0xFF;
                    sprintf(sock_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

                    sock = socket(AF_INET, SOCK_DGRAM, 0);
                    addr.sin_family = AF_INET;
                    inet_aton(sock_ip, &addr.sin_addr);
                    addr.sin_port = htons(AITF_PORT);
                    free(sock_ip);
                    msg = cease.serialize();
                    msg_size = sizeof(int) * 4 + 8 + FLOW_SIZE;
                    if (sendto(sock, msg, msg_size, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
                        printf("Failed to send AITF cease\n");
                    free(msg);
                }
                break;
            case AITF_ACK:
                // Request/action should have been taken
                // Don't need to verify since packet requires no action and
                // can therefore be dropped regardless, so just remove entries
                remove_filter(pkt->dest_ip, pkt->src_ip);
                free(nonce_data[pkt->dest_ip]);
                seq_data.erase(pkt->dest_ip);
                nonce_data.erase(pkt->dest_ip);
                ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
                if (ret == -1) printf("Failed to set verdict\n");
                return ret;
            case AITF_REQ:
                //Request from victim gateway
                resp = handle_victim_request(pkt);
                if (resp.getSrc_ip() == 0 && resp.getDest_ip()) {
                    ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
                    if (ret == -1) printf("Failed to set verdict\n");
                    return ret;
                }
                for (int i = 0; i < 6; i++) {
                    if (f.ips[i] != 0) {
                        request_dest_ip = f.ips[i];
                        break;
                    }
                }
                break;
            case 6: //AITF_CEASE_ACK
                for (int i = 0; i < filters.size(); i++) {
                    if (filters[i].getSrc_ip() == htonl(src_ip)) {
                        remove_filter(i);
                    }
                }
                break;
            default:
                ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
                if (ret == -1) printf("Failed to set verdict\n");
                return ret;
        }
        ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
        if (ret == -1) {
            printf("Failed to set verdict\n");
            return ret;
        }

        filt.last_gw = request_dest_ip;

        sock_ip = create_str(20);
        bytes[3] = request_dest_ip & 0xFF;
        bytes[2] = (request_dest_ip >> 8) & 0xFF;
        bytes[1] = (request_dest_ip >> 16) & 0xFF;
        bytes[0] = (request_dest_ip >> 24) & 0xFF;
        sprintf(sock_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        addr.sin_family = AF_INET;
        inet_aton(sock_ip, &addr.sin_addr);
        addr.sin_port = htons(AITF_PORT);
        free(sock_ip);
        msg = resp.serialize();
        msg_size = sizeof(int) * 4 + 8 + FLOW_SIZE;
        if (sendto(sock, msg, msg_size, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
            printf("Failed to send AITF response\n");
        free(msg);
        return ret;
    }/*}}}*/

    /**
     * Adds a new filter to the filter tables
     * @param f the filter line to add
     */
    bool nfq_router::addFilter(filter_line f) {/*{{{*/
        // For each filter
        for (int i = 0; i < filters.size(); i++) {
            // If the filter matches
            if (filters[i].get_dest() == f.get_dest() && f.getSrc_ip() == filters[i].getSrc_ip()) {
                // Check filter expiration times, reset attack count if expired
                if (filters[i].is_active()) {
                    return false;     //we already have an active filter, do nothing
                }
                if (filters[i].attack_time + FILTER_DURATION < time(NULL)) {    //has expired
                    filters[i].attack_count = 1;
                    filters[i].attack_time = time(NULL);
                    filters[i].activate();
                    return false;
                }
                    // Otherwise just increment
                else {
                    filters[i].attack_count++;
                    filters[i].attack_time = time(NULL);
                }
                // If over threshold for end hosts and gateways
                if (filters[i].attack_count >= 2) {
                    // Check if attacker is an endhost
                    for (int j = 0; j < subnet.size(); j++) {
                        if (f.getSrc_ip() == htonl(subnet[j].ip)) {
                            AITFPacket resp(7); // AITF_DISCONNECT
                            char *sock_ip = create_str(20);
                            char bytes[4];
                            bytes[3] = f.getSrc_ip() & 0xFF;
                            bytes[2] = (f.getSrc_ip() >> 8) & 0xFF;
                            bytes[1] = (f.getSrc_ip() >> 16) & 0xFF;
                            bytes[0] = (f.getSrc_ip() >> 24) & 0xFF;
                            sprintf(sock_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

                            int sock = socket(AF_INET, SOCK_DGRAM, 0);
                            struct sockaddr_in addr;
                            addr.sin_family = AF_INET;
                            inet_aton(sock_ip, &addr.sin_addr);
                            addr.sin_port = htons(AITF_PORT);
                            free(sock_ip);
                            char *msg = resp.serialize();
                            int msg_size = sizeof(int) * 4 + 8 + FLOW_SIZE;
                            if (sendto(sock, msg, msg_size, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
                                printf("Failed to send disconnect message\n");
                            free(msg);

                            return true;
                        }
                    }
                    if (filters[i].attack_count >= 3) {
                        filters[i].activate();
                        escalate(f, f.get_flow());
                        // TODO make new filter - fixed above?
                    }
                }
                return false;
            }
        }
        filters.push_back(f);
        return false;
    }/*}}}*/

/**
     * Adds the flow to a packet
     * @param old_payload the old packet
     * @param f the flow to add
     * @param pkt_size the size of the packet
     * @return the updated packet
     */
    unsigned char *nfq_router::update_pkt(unsigned char *old_payload, Flow *f, int pkt_size, bool pre) {/*{{{*/
        unsigned char *new_payload = create_ustr(pkt_size + FLOW_SIZE + 8);


        memcpy(new_payload, old_payload, sizeof(struct iphdr));

        char *fs = f->serialize();
        //for (int i = 0; i < FLOW_SIZE; i++) new_payload[sizeof(struct iphdr) + 8 + i] = fs[i];
        memcpy(new_payload + sizeof(struct iphdr) + 8, fs, FLOW_SIZE);
        free(fs);
        memcpy(new_payload + sizeof(struct iphdr) + FLOW_SIZE + 8, old_payload + sizeof(struct iphdr),
               pkt_size - sizeof(struct iphdr));
        ((struct iphdr *) new_payload)->tot_len = htons(pkt_size + FLOW_SIZE + 8);


        return new_payload;
    }/*}}}*/

    /**
     * Update route record layer as appropriate for network position
     * and replace current packet in kernel
     * @param payload
     * @param flow
     */
    int nfq_router::handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload,
                                 Flow *flow) {/*{{{*/
        bool pre = (flow == NULL);
        unsigned int src_ip = ((struct iphdr *) payload)->saddr;
        unsigned int dest_ip = ((struct iphdr *) payload)->daddr;
        unsigned char *s_d = create_ustr(15);
        sprintf((char *) s_d, "%d\n", dest_ip);
        unsigned char *hash = HMAC(EVP_md5(), key, strlen(key), s_d, strlen((char *) s_d), NULL, NULL);
        free(s_d);


        unsigned char *new_pkt;
        // If in filters, drop it
        if (check_filters(flow, (char *) hash, dest_ip, src_ip)) {
            return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
            // If going to legacy host, discard RR record
        } else if (to_legacy_host(dest_ip)) {
            new_pkt = strip_rr(payload, pkt_size);
            if (flow != NULL)
                ((struct iphdr *) new_pkt)->tot_len = htons(pkt_size - FLOW_SIZE - 8);
        } else if (flow == NULL) {
            flow = new Flow();
            flow->add_hop(ip, (char *) hash);
            // Insert a flow in the middle of the IP header and the rest of the packet
            new_pkt = update_pkt(payload, flow, pkt_size, pre);
            // Otherwise I am an intermediary router, so add myself as a hop
        } else {
            //flow->add_hop(ip, (char*)hash);
            unsigned char *tmp = strip_rr(payload, pkt_size);
            new_pkt = update_pkt(tmp, flow, pkt_size - FLOW_SIZE - 8, pre);
            free(tmp);
        }
        int np_size = ntohs(((struct iphdr *) new_pkt)->tot_len);
        compute_ip_checksum((struct iphdr *) new_pkt);


        int ret = nfq_set_verdict(qh, pkt_id, NF_ACCEPT, np_size, new_pkt);
        free(new_pkt);
        if (ret == -1) printf("Failed to set verdict\n");
        return ret;
    }/*}}}*/

    /**
     * Determines if the packet is being sent to one of the routers legacy hosts
     * @return true if sent to legacy host in subnet, false otherwise
     */
    bool nfq_router::to_legacy_host(int ipIn) {/*{{{*/
        for (int i = 0; i < subnet.size(); i++) {
            if (subnet[i].ip == ipIn && subnet[i].legacy) {
                return true;
            }
        }
        return false;
    }/*}}}*/

    /**
     * Removes a filter based on array index
     * @param filter index
     */
    void nfq_router::remove_filter(int index) {/*{{{*/
        filters[index].set_active(false);
    }/*}}}*/

    /**
     * Removes a filter based on destination IP
     * @param destination IP
     */
    void nfq_router::remove_filter(unsigned dest, unsigned src) {/*{{{*/
        for (int i = 0; i < filters.size(); i++) {
            if (filters[i].get_dest() == dest && filters[i].getSrc_ip() == src) {
                filters[i].set_active(false);
                break;
            }
        }
    }/*}}}*/

    /**
     * Begin escalation process
     * @param filt
     * @param f
     */
    void nfq_router::escalate(filter_line filt, Flow *f) {/*{{{*/
        if (f == NULL) {
            printf("No flow data! Cannot escalate!\n");
            return;
        }
        printf("esc\n");
        unsigned next_gw = 0;
        for (int i = 0; i < 6; i++) {
            if (f->ips[i] != 0 && f->ips[i] == filt.last_gw) {
                next_gw = f->ips[i + 1];
                f->ips[i] = 0;
//                strcpy(f->hashes[i], "00000000");
                break;
            }
            // Otherwise we have already tried this gateway, so remove it from the flow
            // since it won't be in the RR layer
        }
        if (!next_gw || next_gw == ip) {
            // TODO set local filter as permanent
        } else {
            unsigned short seq;
            char nonce[8];
            RAND_bytes((unsigned char *) &seq, 2);
            RAND_bytes((unsigned char *) nonce, 8);
            AITFPacket esc(AITF_HELO, seq, nonce);
            vector<int> pkt_ips(6);
            for (int i = 0; i < 6; i++) pkt_ips[i] = f->ips[i];
            esc.set_flow(pkt_ips);
            vector <char *> h;
            for (int i = 0; i < 6; i++){
                h.push_back(create_str(8));
                memcpy(h[i], f->hashes[i], 8);
            }
            esc.set_hashes(h);
            esc.src_ip = filt.getSrc_ip();
            esc.dest_ip = filt.get_dest();
            seq_data[esc.dest_ip] = seq;
            char *sock_ip = create_str(20);
            char bytes[4];
            bytes[3] = next_gw & 0xFF;
            bytes[2] = (next_gw >> 8) & 0xFF;
            bytes[1] = (next_gw >> 16) & 0xFF;
            bytes[0] = (next_gw >> 24) & 0xFF;
            sprintf(sock_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            inet_aton(sock_ip, &addr.sin_addr);
            addr.sin_port = htons(AITF_PORT);
            free(sock_ip);
            char *msg = esc.serialize();
            int msg_size = sizeof(int) * 4 + 8 + FLOW_SIZE;
            if (sendto(sock, msg, msg_size, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
                printf("Failed to send AITF escalation\n");
            free(msg);
        }
    }/*}}}*/

    /**
     * Check if received packet violates a filter
     * @param flow the packet's flow or NULL if no flow
     * @param dest the packet's destination
     * @param src the packet's source
     * @return true if packet should be dropped, false otherwise
     */
    bool nfq_router::check_filters(Flow *flow, char *hash, unsigned dest, unsigned src) {/*{{{*/
        if (flow != NULL)
            flow->add_hop(ip, hash);
        vector<int> indexes;
        unsigned d_ip, s_ip;
        d_ip = htonl(dest);
        s_ip = htonl(src);
        for (int i = 0; i < filters.size(); i++) {
            if (!filters[i].is_active()) continue;

            // If filter has expired
            if (filters[i].check_expire()) {
                if (filters[i].get_temp()) {
                    bool insub = false;
                    for (int j = 0; j < subnet.size(); j++) {
                        if (subnet[j].ip == htonl(filters[i].getSrc_ip())) {
                            insub = true;
                        }
                    }
                    if (insub) {
                        AITFPacket cease(7); //AITF_DISCONNECT
                        char *sock_ip;
                        unsigned char bytes[4];
                        int sock;
                        struct sockaddr_in addr;
                        char *msg;
                        int msg_size;
                        // Send cease request to attacker
                        sock_ip = create_str(20);
                        bytes[3] = filters[i].getSrc_ip() & 0xFF;
                        bytes[2] = (filters[i].getSrc_ip() >> 8) & 0xFF;
                        bytes[1] = (filters[i].getSrc_ip() >> 16) & 0xFF;
                        bytes[0] = (filters[i].getSrc_ip() >> 24) & 0xFF;
                        sprintf(sock_ip, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

                        sock = socket(AF_INET, SOCK_DGRAM, 0);
                        addr.sin_family = AF_INET;
                        inet_aton(sock_ip, &addr.sin_addr);
                        addr.sin_port = htons(AITF_PORT);
                        free(sock_ip);
                        msg = cease.serialize();
                        msg_size = sizeof(int) * 4 + 8 + FLOW_SIZE;
                        if (sendto(sock, msg, msg_size, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
                            printf("Failed to send AITF cease\n");
                        free(msg);
                    } else
                        escalate(filters[i], flow);

                } else {
                    // Insert entries into beginning of vector to avoid changing indices on removal
                    indexes.insert(indexes.begin(), i);
                    continue;
                }
            }
            if (filters[i].trigger_filter(d_ip, s_ip, flow)) {
                return true;
            }
        }

        for (int i = 0; i < indexes.size(); i++)
            remove_filter(indexes[i]);
        return false;
    }/*}}}*/
}
