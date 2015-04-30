//
// Created by lhunker on 4/29/15.
//

#ifndef AITF_FILTER_LINE_H
#define AITF_FILTER_LINE_H

#include "../shared_libs/aitf_prot.h"
#include <stdlib.h>

namespace aitf {
    class filter_line {
    public:
        filter_line(unsigned dest, Flow f, unsigned src = 0);

        filter_line(unsigned dest, unsigned src = 0);

        const bool trigger_filter(unsigned dest, unsigned src, Flow *f);

    private:
        unsigned dest_ip;
        unsigned src_ip;
        Flow flow;
        bool hasFlow;
    };
}


#endif //AITF_FILTER_LINE_H
