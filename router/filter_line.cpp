//
// Created by lhunker on 4/29/15.
//

#include "filter_line.h"

namespace aitf {
    filter_line::filter_line(unsigned dest, Flow f, bool t, unsigned src) {/*{{{*/
        dest_ip = dest;
        src_ip = src;
        flow = f;
        hasFlow = true;
        create_time = time(NULL);
        active = true;
        attack_count = 1;
        attack_time = time(NULL);
        temp = t;
    }

    /*}}}*/

    filter_line::filter_line(unsigned dest, bool t, unsigned src) {/*{{{*/
        dest_ip = dest;
        src_ip = src;
        hasFlow = false;
        create_time = time(NULL);
        active = true;
        attack_count = 1;
        attack_time = time(NULL);
        temp = t;
    }

    /*}}}*/

    filter_line::filter_line() {/*{{{*/
        dest_ip = 0;
        src_ip = 0;
        hasFlow = false;
        create_time = time(NULL);
        active = true;
        attack_count = 1;
        attack_time = time(NULL);
    }/*}}}*/

    /**
     * Returns active state
     * @return true if active
     */
    bool filter_line::is_active() {/*{{{*/
        return active;
    }/*}}}*/

    /**
     * Sets active state
     * @param a active state
     */
    void filter_line::set_active(bool a) {/*{{{*/
        active = a;
    }/*}}}*/

    /**
     * Gets flow
     * @return flow
     */
    Flow *filter_line::get_flow() {/*{{{*/
        return &flow;
    }/*}}}*/

    /**
     * Gets destination IP
     * @return dest ip
     */
    unsigned filter_line::get_dest() {/*{{{*/
        return dest_ip;
    }

    /*}}}*/

    void filter_line::setIps(unsigned dest, unsigned int src, bool t) {/*{{{*/
        dest_ip = dest;
        src_ip = src;
        hasFlow = false;
        create_time = time(NULL);
        temp = t;
    }/*}}}*/

    bool filter_line::get_temp() {
        return temp;
    }

    void filter_line::activate() {
        active = true;
    }

/**
     * Checks if the filter is still valid
     * @return true if filter is expired
     */
    bool filter_line::check_expire() {/*{{{*/
        if (temp) {
            return attack_time + FILTER_EXPIRE < time(NULL);
        } else {
            return attack_time + FILTER_DURATION < time(NULL);
        }

    }

    /*}}}*/

    void filter_line::debugPrint() {/*{{{*/
        flow.debugPrint();
        printf("Filter src: %u, Filter dest: %u\n", src_ip, dest_ip);
    }/*}}}*/

    /**
     * Checks whether a given dest ip, src ip and flow are triggered by this filter
     * @param dest the destination ip address of the packet
     * @param src the source ip of the packet
     * @param f the flow of the packet
     * @return true if the packet should be dropped, false otherwise
     */
    const bool filter_line::trigger_filter(unsigned dest, unsigned src, Flow *f) {/*{{{*/
        if (!is_active()) { return false; }
        //if filter doesn't have source defined, just check flow and dest
        if (hasFlow && src_ip == 0 && f != NULL && *f == flow && dest == dest_ip) {
            return true;
            // If no flow is defined in filter, just check ips
        } else if ((!hasFlow || f == NULL) && dest == dest_ip && src == src_ip) {
            return true;
            //otherwise compare all three
        } else return hasFlow && f != NULL && flow == *f && dest == dest_ip && src == src_ip;
    }/*}}}*/
}
