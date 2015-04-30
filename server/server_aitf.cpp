#include "server_aitf.h"
#include "../router/checksum.h"

namespace aitf {
    Server::Server() {/*{{{*/
        flows = new FlowPaths();
    }/*}}}*/

    Server::~Server() {/*{{{*/
        delete flows;
    }/*}}}*/

    int Server::handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, unsigned int dest_ip, AITFPacket *pkt) {/*{{{*/
        // TODO: will this ever actually receive one of these?
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, NULL);
    }/*}}}*/

    /**
     * Removes route record from packet and checks attack threshold
     * @param payload
     * @param flow
     */
    int Server::handlePacket(struct nfq_q_handle *qh, int pkt_id, int pkt_size, unsigned char *payload,
                             Flow *flow) {/*{{{*/
        unsigned int src_ip = ((struct iphdr *) payload)->saddr;
        Flow f;
        char *fs = flow->serialize();
        f.populate(fs);
        free(fs);
        flows->add_flow(f, src_ip); //TODO put threshold check in add
        unsigned char *new_pkt;
        new_pkt = strip_rr(payload, pkt_size);
        if (flow != NULL)
            ((struct iphdr *) new_pkt)->tot_len = htons(pkt_size - FLOW_SIZE - 8);
        int np_size = ntohs(((struct iphdr *) new_pkt)->tot_len);
        compute_ip_checksum((struct iphdr *) new_pkt);
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, np_size, new_pkt);
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
                        }
                    }
                }
                pkt_count[i].push_back(0);
                pkt_times[i].push_back(time(NULL));
                src_ips[i].push_back(src_ip);
            }
        }
        // No resize is necessary as the vector library reallocates as necessary
        route_ips.push_back(flow);
        pkt_count.push_back(vector<int>(5));
        pkt_count[pkt_count.size() - 1].push_back(1);
        pkt_times.push_back(vector<int>(5));
        pkt_times[pkt_times.size()].push_back(time(NULL));
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

    /**
     * Checks attack threshold for a given flow
     * @param flow
     * @return true if over threshold
     */
    bool FlowPaths::check_attack_threshold(Flow flow) {/*{{{*/
//        for (int i = 0; i < route_ips.size(); i++) {
//            if (route_ips[i] == flow) {
//                if (pkt_count[i] > PKT_THRESHOLD)
//                    return true;
//                return false;
//            }
//        }
        return false;
    }/*}}}*/
}
