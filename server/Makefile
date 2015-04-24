all:
	clang++ -Wall -D__USE_MISC -D_BSD_SOURCE server_legacy.cpp server_legacy_main.cpp ../shared_libs/aitf_nf.cpp ../shared_libs/aitf_prot.cpp ../shared_libs/common.cpp -o router -lnetfilter_queue -lssl -lcrypto
