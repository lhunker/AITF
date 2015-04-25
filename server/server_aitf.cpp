#include "server_aitf.h"

namespace aitf {
    Server::Server() {/*{{{*/
        flows = new FlowPaths();
    }/*}}}*/

    Server::~Server() {/*{{{*/
        delete flows;
    }/*}}}*/

    int Server::handle_aitf_pkt(struct nfq_q_handle *qh, int pkt_id, AITFPacket *pkt) {/*{{{*/
        // TODO: will this ever actually receive one of these?
        return nfq_set_verdict(qh, pkt_id, AITF_ACCEPT_PACKET, 0, NULL);
    }/*}}}*/

    /**
     * Removes route record from packet and checks attack threshold
     * @param payload
     * @param flow
     */
    int Server::handlePacket(struct nfq_q_handle *qh, int pkt_id, unsigned char *payload, Flow *flow) {/*{{{*/
        flows->add_flow(*flow);
        if (flows->check_attack_threshold(*flow)) {
            // TODO: send filter request
        } else {
            unsigned char *new_payload = create_ustr(strlen((char*)payload) - 64 - sizeof(Flow));
            strncpy((char*)new_payload, (char*)payload, sizeof(struct iphdr));
            strcpy((char*)new_payload, (char*)payload[sizeof(struct iphdr) + 64 + sizeof(Flow)]);
            // TODO: reinsert new_payload as packet
        }
        return nfq_set_verdict(qh, pkt_id, AITF_ACCEPT_PACKET, 0, NULL);
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
     * @param flow
     */
    void FlowPaths::add_flow(Flow flow) {/*{{{*/
        // Check if flow already exists in table
        for (int i = 0; i < route_ips.size(); i++) {
            // If yes, check that time hasn't expired and either reset
            // or increment count
            if (route_ips[i] == flow) {
                if (pkt_times[i] + PKT_TIMEOUT < time(NULL)) {
                    reset_count(i);
                    return;
                } else {
                    pkt_count[i]++;
                    // TODO: Check attack threshold here
                    return;
                }
            }
        }
        // No resize is necessary as the vector library reallocates as necessary
        route_ips.push_back(flow);
        pkt_count.push_back(0);
        pkt_times.push_back(time(NULL));
    }/*}}}*/

    /**
     * Resets packet count for a given flow index
     * @param flow
     */
    void FlowPaths::reset_count(int flow) {/*{{{*/
        // Triggered upon packet reception, hence 1 instead of 0
        pkt_count[flow] = 1;
        pkt_times[flow] = time(NULL);
    }/*}}}*/

    /**
     * Checks attack threshold for a given flow
     * @param flow
     * @return true if over threshold
     */
    bool FlowPaths::check_attack_threshold(Flow flow) {/*{{{*/
        for (int i = 0; i < route_ips.size(); i++) {
            if (route_ips[i] == flow) {
                if (pkt_count[i] > PKT_THRESHOLD)
                    return true;
                return false;
            }
        }
        return false;
    }/*}}}*/
}
