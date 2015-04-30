all:
	clang++ -Wall -D__USE_MISC -D_BSD_SOURCE server_aitf.cpp server_main.cpp ../shared_libs/aitf_nf.cpp ../shared_libs/aitf_prot.cpp ../shared_libs/common.cpp -o aitf_server -lnetfilter_queue -lssl -lcrypto
