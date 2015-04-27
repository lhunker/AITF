echo "The second line of this file NEGATES the second. You should not run this file"
exit 0
iptables -A INPUT -j NFQUEUE --queue-num 0
iptables --flush
