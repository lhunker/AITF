using std::string;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) {/*{{{*/
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        //printf("hw_protocol=0x%04x hook=%u id=%u ",
            //ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        //printf("hw_src_addr=");
        //for (i = 0; i < hlen-1; i++)
            //printf("%02x:", hwph->hw_addr[i]);
        //printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    //if (mark)
        //printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    //if (ifi)
        //printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    //if (ifi)
        //printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    //if (ifi)
        //printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    //if (ifi)
        //printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        //printf("payload_len=%d, payload=%s\n", ret, data);
        struct iphdr *ip_info = (struct iphdr*)data;
        //printf("%d\n", ip_info->tot_len);
        //for (int i = 0; i < 4096; i++) {printf("%c", data[i]);}
        //printf("Packet size: %d\n", sizeof(&ip_info));
        if (ip_info->protocol == IPPROTO_TCP) {
           struct tcphdr *tcp_info = (struct tcphdr*)(data + sizeof(*ip_info));
           unsigned short dest_port = ntohs(tcp_info->dest);
        }
    }

    //fputc('\n', stdout);

    return id;
}/*}}}*/

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,/*{{{*/
          struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    //printf("entering callback\n");
    unsigned char* payload;
    int len = nfq_get_payload(nfa, &payload);
    string pkt;
    pkt.assign((char*)payload, len);
    int pos = pkt.find("documents", 0);
    if (pos > 0) {
        pkt.replace(pos, 1, "D");
        unsigned char* newpkt = (unsigned char*)pkt.c_str();
        len = pkt.size();
        printf("Accepting modified packet\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, newpkt);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}/*}}}*/

static int callBack(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
 int len=0,id=0;
 unsigned char *pktData;
 string pktString;
 struct nfqnl_msg_packet_hdr *pktHeader;
 pktHeader = nfq_get_msg_packet_hdr(nfa);
 if (pktHeader) 
 {
   id = ntohl(pktHeader->packet_id);
 }
 len = nfq_get_payload(nfa, &pktData);
 if(len) 
 {
  int pos;
  pktString.assign((char*)pktData,len);
  pos=pktString.find("documents",0);
  if(pos>0)
 {
    printf("modify\n");
    //pktString.insert(sizeof(struct iphdr*),"datadatadatadatadatadatadatadata");
    int pos = pktString.find("200 OK");
    if (pos) {pktString.replace(pos, 15, "404 NOT FOUND");}
    unsigned char* newPktData=(unsigned char*)pktString.c_str();
    for (int i = 0; i < len; i++) {if (newPktData[i] != pktData[i]) {printf("Modified\n"); break;}}
    //nfq_ip_set_checksum((struct iphdr*)newPktData);
    len=pktString.size();
    return nfq_set_verdict(qh, id, NF_ACCEPT,len,newPktData);
 }
}   
return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {/*{{{*/
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &callBack, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    nfq_set_queue_maxlen(qh, 3200);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}/*}}}*/
