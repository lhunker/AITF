all:
	clang++ -Wall -g -D__USE_MISC -D_BSD_SOURCE nfq_router.cpp router_main.cpp filter_line.cpp ../shared_libs/aitf_nf.cpp ../shared_libs/aitf_prot.cpp ../shared_libs/common.cpp checksum.c -o router -lnetfilter_queue -lssl -lcrypto -lnfnetlink
