all:
	clang++ -Wall -g -D__USE_MISC -D_BSD_SOURCE attacker.cpp attacker_main.cpp ../shared_libs/aitf_nf.cpp ../shared_libs/aitf_prot.cpp ../shared_libs/common.cpp -o attacker -lnetfilter_queue -lssl -lcrypto -lnfnetlink
