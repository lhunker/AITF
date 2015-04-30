//
// Created by lhunker on 4/23/15.
//

#include "nfq_router.h"
#include "checksum.h"

namespace aitf {

    nfq_router::nfq_router(vector<endhost> hostIn, char *str_ip) {/*{{{*/
        s_ip = create_str(15);
        strcpy(s_ip, str_ip);
        unsigned int c1,c2,c3,c4;
        sscanf(s_ip, "%d.%d.%d.%d",&c1,&c2,&c3,&c4);
        ip = (unsigned int)c4+c3*256+c2*256*256+c1*256*256*256;

        subnet = vector<endhost>(hostIn);

        old_key = create_str(32);
        key = create_str(32);
        RAND_load_file("/dev/urandom", 1024);
        RAND_bytes((unsigned char*)key, 32);
    }/*}}}*/

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
        RAND_bytes((unsigned char*)key, 32);
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
    AITFPacket nfq_router::handle_victim_request(unsigned int ip, AITFPacket *pkt) {/*{{{*/
        filter_line filt(pkt->getDest_ip(), pkt->get_flow(), pkt->getSrc_ip());
        addFilter(filt);
        //TODO setup adding flow to packet
        unsigned short seq;
        char nonce[8];
        RAND_bytes((unsigned char *) &seq, 2);
        RAND_bytes((unsigned char *) nonce, 8);
        AITFPacket req(AITF_HELO, seq, nonce);
        return req;
    }/*}}}*/

/**
     * Determine mode of AITF packet and respond, taking appropriate action
     * @param pkt
     */
    int nfq_router::handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, unsigned int dest_ip, AITFPacket *pkt) {/*{{{*/
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

        AITFPacket resp;
        int ret;
        switch (pkt->get_mode()) {
            // TODO add way to receive a filtering request from a victim
            case AITF_HELO:
                // If received the first stage, send back sequence +1 and same nonce
                seq_data[dest_ip] = pkt->get_seq();
                nonce_data[dest_ip] = create_str(8);
                strcpy(nonce_data[dest_ip], pkt->get_nonce());
                resp.set_values(AITF_CONF, pkt->get_seq() + 1, pkt->get_nonce());
                break;
            case AITF_CONF:
                // Validate sequence and nonce
                if (seq_data[dest_ip] != (pkt->get_seq() - 1) || strcmp(nonce_data[dest_ip], pkt->get_nonce()) != 0)
                    return clear_aitf_conn(qh, pkt_id, dest_ip);
                // If received the second stage, send back sequence +1 and same nonce
                resp.set_values(AITF_ACT, pkt->get_seq() + 1, pkt->get_nonce());
                break;
            case AITF_ACT:
                // Validate sequence and nonce
                if (seq_data[dest_ip] != (pkt->get_seq() - 1) || strcmp(nonce_data[dest_ip], pkt->get_nonce()) != 0)
                    return clear_aitf_conn(qh, pkt_id, dest_ip);
                // If receiving a third stage packet, add filter
                resp.set_values(AITF_ACK, pkt->get_seq() + 1, pkt->get_nonce());
                // TODO change compliance modes here
//                filters.push_back(pkt->get_flow());
                break;
            case AITF_ACK:
                // Request/action should have been taken
                // Don't need to verify since packet requires no action and
                // can therefore be dropped regardless, so just remove entries
                free(nonce_data[dest_ip]);
                seq_data.erase(dest_ip);
                nonce_data.erase(dest_ip);
                ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
                if (ret == -1) printf("Failed to set verdict\n");
                return ret;
            case AITF_REQ:
                //Request from victim gateway
                resp = handle_victim_request(dest_ip, pkt);
                break;
            default:
                ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
                if (ret == -1) printf("Failed to set verdict\n");
                return ret;
        }
        // TODO send resp packet
        ret = nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
        if (ret == -1) printf("Failed to set verdict\n");
        return ret;
    }/*}}}*/

    /**
     * Adds a new filter to the filter tables
     * @param f the filter line to add
     */
    void nfq_router::addFilter(filter_line f) {
        filters.push_back(f);
    }

/**
     * Adds the flow to a packet
     * @param old_payload the old packet
     * @param f the flow to add
     * @param pkt_size the size of the packet
     * @return the updated packet
     */
    unsigned char *nfq_router::update_pkt(unsigned char *old_payload, Flow *f, int pkt_size, bool pre) {/*{{{*/
        unsigned char *new_payload = create_ustr(pkt_size + FLOW_SIZE + 8);

        if (!pre) {
            FILE *fp = fopen("caps/pre_mod", "w+");
            for (int i = 0; i < pkt_size; i++) fputc(old_payload[i], fp);
            fclose(fp);
        }

        memcpy(new_payload, old_payload, sizeof(struct iphdr));

        char *fs = f->serialize();
        //for (int i = 0; i < FLOW_SIZE; i++) new_payload[sizeof(struct iphdr) + 8 + i] = fs[i];
        memcpy(new_payload + sizeof(struct iphdr) + 8, fs, FLOW_SIZE);
        free(fs);
        printf("size: %lu\n", (pkt_size - sizeof(struct iphdr)));
        memcpy(new_payload + sizeof(struct iphdr) + FLOW_SIZE + 8, old_payload + sizeof(struct iphdr), pkt_size - sizeof(struct iphdr));
        ((struct iphdr*)new_payload)->tot_len = htons(pkt_size + FLOW_SIZE + 8);

        if (!pre) {
            FILE *fp = fopen("caps/post_mod", "w+");
            for (int i = 0; i < pkt_size + FLOW_SIZE + 8; i++) fputc(new_payload[i], fp);
            fclose(fp);
        }

        return new_payload;
    }/*}}}*/

    /**
     * Update route record layer as appropriate for network position
     * and replace current packet in kernel
     * @param payload
     * @param flow
     */
    int nfq_router::handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload, Flow *flow) {/*{{{*/
        bool pre = (flow == NULL);
        unsigned int src_ip = ((struct iphdr*)payload)->saddr;
        unsigned int dest_ip = ((struct iphdr*)payload)->daddr;
        unsigned char *s_d = create_ustr(15);
        sprintf((char*)s_d, "%d\n", dest_ip);
        unsigned char *hash = HMAC(EVP_md5(), key, strlen(key), s_d, strlen((char*)s_d), NULL, NULL);

        if (!pre) {
            FILE *fp = fopen("caps/pre_handle", "w+");
            for (int i = 0; i < pkt_size; i++) fputc(payload[i], fp);
            fclose(fp);
        }

        unsigned char *new_pkt;
        // If in filters, drop it
        if (check_filters(flow, dest_ip, src_ip)) {
            return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
            // If going to legacy host, discard RR record
        } else if (to_legacy_host(dest_ip)) {
            new_pkt = strip_rr(payload, pkt_size);
            if (flow != NULL)
                ((struct iphdr *) new_pkt)->tot_len = htons(pkt_size - FLOW_SIZE - 8);
        } else if (flow == NULL) {
            flow = new Flow();
            flow->add_hop(ip, (char*)hash);
            // Insert a flow in the middle of the IP header and the rest of the packet
            new_pkt = update_pkt(payload, flow, pkt_size, pre);
            // Otherwise I am an intermediary router, so add myself as a hop
        } else {
            flow->add_hop(ip, (char*)hash);
            unsigned char *tmp = strip_rr(payload, pkt_size);
            new_pkt = update_pkt(tmp, flow, pkt_size - FLOW_SIZE - 8, pre);
            free(tmp);
        }
        int np_size = ntohs(((struct iphdr*)new_pkt)->tot_len);
        compute_ip_checksum((struct iphdr*)new_pkt);

        if (!pre) {
            FILE *fp = fopen("caps/post_handle", "w+");
            for (int i = 0; i < np_size; i++) fputc(new_pkt[i], fp);
            fclose(fp);
        }

        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, np_size, new_pkt);
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
     * Check if received packet violates a filter
     * @param flow the packet's flow or NULL if no flow
     * @param dest the packet's destination
     * @param src the packet's source
     * @return true if packet should be dropped, false otherwise
     */
    bool nfq_router::check_filters(Flow *flow, unsigned dest, unsigned src) {/*{{{*/
        for (int i = 0; i < filters.size(); i++) {
            if (filters[i].trigger_filter(dest, src, *flow)) {
                return true;
            }
        }
        return false;
    }/*}}}*/
}


