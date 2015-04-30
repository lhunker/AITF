//
// Created by lhunker on 4/29/15.
//

#include "filter_line.h"

namespace aitf {
    filter_line::filter_line(unsigned dest, Flow f, unsigned src) {
        dest_ip = dest;
        src_ip = src;
        flow = f;
        hasFlow = true;
    }

    filter_line::filter_line(unsigned dest, unsigned src) {
        dest_ip = dest;
        src_ip = src;
        hasFlow = false;
    }

    /**
     * Checks whether a given dest ip, src ip and flow are triggered by this filter
     * @param dest the destination ip address of the packet
     * @param src the source ip of the packet
     * @param f the flow of the packet
     * @return true if the packet should be dropped, false otherwise
     */
    const bool filter_line::trigger_filter(unsigned dest, unsigned src, Flow f) {
        //if filter doesn't have source defined, just check flow and dest
        if (src_ip == 0 && f == flow && dest == dest_ip) {
            return true;
            // If no flow is defined in filter, just check ips
        } else if (!hasFlow && dest == dest_ip && src == src_ip) {
            return true;
            //otherwise compare all three
        } else return flow == f && dest == dest_ip && src == src_ip;
    }
}
