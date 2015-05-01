//
// Created by lhunker on 4/29/15.
//

#ifndef AITF_FILTER_LINE_H
#define AITF_FILTER_LINE_H

#include "../shared_libs/aitf_prot.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#define FILTER_EXPIRE 10
#define FILTER_DURATION 30

namespace aitf {
    class filter_line {
    public:
        filter_line(unsigned dest, Flow f, bool t, unsigned int src);

        filter_line(unsigned dest, bool t, unsigned int src);

        filter_line();

        const bool trigger_filter(unsigned dest, unsigned src, Flow *f);

        unsigned int getSrc_ip() const {
            return src_ip;
        }

        void setIps(unsigned dest, unsigned int src, bool t);
        void debugPrint();

        unsigned get_dest();

        Flow* get_flow();

        bool check_expire();

        bool is_active();
        void set_active(bool);

        bool get_temp();
        int attack_time;
        int attack_count;

        void activate();
    private:
        bool active;
        int create_time;
        unsigned dest_ip;
        unsigned src_ip;
        Flow flow;
        bool hasFlow;
        bool temp;
    };
}


#endif //AITF_FILTER_LINE_H
