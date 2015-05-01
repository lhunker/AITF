#include "server_aitf.h"
#include "../router/checksum.h"

namespace aitf {
    Server::Server() {/*{{{*/
        flows = new FlowPaths();
    }/*}}}*/

    Server::~Server() {/*{{{*/
        delete flows;
    }/*}}}*/

    int Server::handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, unsigned int src_ip, unsigned int dest_ip,
                                AITFPacket *pkt) {/*{{{*/
        // TODO: will this ever actually receive one of these?
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
    }/*}}}*/

    void FlowPaths::sendFilterRequest(Flow f, int ip) {
        f.debugPrint();

        AITFPacket req(AITF_REQ, htonl(ip), f);
        req.dest_ip = 168036865; //TODO shouldn't be hardcoded
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        char *sock_ip = "10.4.10.2";
        inet_aton(sock_ip, &addr.sin_addr);
        addr.sin_port = htons(AITF_PORT);
        char *msg = req.serialize();
        if (sendto(sock, msg, sizeof(AITFPacket), 0, (struct sockaddr *) &addr, sizeof(addr)) < 0)
            printf("Failed to send AITF response\n");
        free(msg);
    }

    /**
     * Removes route record from packet and checks attack threshold
     * @param payload
     * @param flow
     */
    int Server::handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload,
                             Flow *flow) {/*{{{*/
        unsigned int src_ip = ((struct iphdr *) payload)->saddr;
        if (flow != NULL)
            flows->add_flow(*flow, src_ip); //TODO put threshold check in add
        unsigned char *new_pkt;
        new_pkt = strip_rr(payload, pkt_size);
        if (flow != NULL)
            ((struct iphdr *) new_pkt)->tot_len = htons(pkt_size - FLOW_SIZE - 8);
        int np_size = ntohs(((struct iphdr *) new_pkt)->tot_len);
        compute_ip_checksum((struct iphdr *) new_pkt);
        int ret = nfq_set_verdict(qh, pkt_id, NF_ACCEPT, np_size, new_pkt);
        if (ret == -1) printf("Failed to set verdict\n");
        free(new_pkt);
        return ret;
    }/*}}}*/

    FlowPaths::FlowPaths() {/*{{{*/
        // This is a data structure wrapper, essentially
        // Only needs to initialize variables
        vector<Flow> route_ips(10);
        vector<int> pkt_count(10);
        vector<int> pkt_times(10);
    }/*}}}*/

    /**
     * Adds a given flow, or increments the packet count
     * Also resets the packet count when appropriate
     * @param flow the flow to add
     * @param src_ip, the ip the attack was sent to
     */
    void FlowPaths::add_flow(Flow flow, unsigned src_ip) {/*{{{*/
        // Check if flow already exists in table

        for (int i = 0; i < route_ips.size(); i++) {
            // If yes, check that time hasn't expired and either reset
            // or increment count
            if (route_ips[i] == flow) {
                for (int j = 0; j < src_ips[i].size(); j++) {
                    if (src_ips[i][j] == src_ip) {
                        if (pkt_times[i][j] + PKT_TIMEOUT < time(NULL)) {
                            reset_count(i, j);
                            return;
                        } else {
                            pkt_count[i][j]++;
                            if (check_attack_thres_flow(i, j)) {
                                sendFilterRequest(flow, src_ip);
                            }
                            return;
                        }
                    }
                }
                pkt_count[i].push_back(0);
                pkt_times[i].push_back(time(NULL));
                src_ips[i].push_back(src_ip);
                reset_times(i);

                if (check_attack_thres_ip(i)) {
                    sendFilterRequest(flow, 0);
                }
                return;
            }
        }
        // No resize is necessary as the vector library reallocates as necessary
        route_ips.push_back(flow);
        pkt_count.push_back(vector<int>(5));
        pkt_count[pkt_count.size() - 1].push_back(1);
        pkt_times.push_back(vector<int>(5));
        pkt_times[pkt_times.size() - 1].push_back(time(NULL));
        src_ips.push_back(vector<unsigned>(5));
        src_ips[src_ips.size() - 1].push_back(src_ip);
    }/*}}}*/

    /**
     * Resets packet count for a given flow index
     * @param flow
     */
    void FlowPaths::reset_count(int flow, int ip) {/*{{{*/
        // Triggered upon packet reception, hence 1 instead of 0
        pkt_count[flow][ip] = 1;
        pkt_times[flow][ip] = time(NULL);
    }/*}}}*/

    void FlowPaths::reset_times(int flow) {
        for (int i = 0; i < src_ips[i].size(); i++) {
            if (pkt_times[flow][i] + PKT_TIMEOUT < time(NULL)) {
                pkt_times[flow][i] = time(NULL);
                pkt_count[flow][i] = 0;
            }
        }
    }

    bool FlowPaths::check_attack_thres_flow(int flow, int i) {
        return (pkt_count[flow][i] > PKT_THRESHOLD);
    }

    bool FlowPaths::check_attack_thres_ip(int flow) {
        int sum = 0;
        for (int i = 0; i < src_ips[flow].size(); i++) {
            sum += pkt_count[flow][i];
        }
        return sum > FLOW_THRESHOLD;
    }


}
