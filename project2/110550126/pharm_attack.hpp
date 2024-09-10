
#include "attacker.hpp"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/udp.h>

#include <csignal>
#include <string>
#include <vector>
using namespace std;



class PHARM: public Attacker{
public:
    PHARM(char *interface);
    void make_device();
    void receive_reply();
    void modify_packet(array<uint8_t, IP_MAXPACKET> &packet);
    void redirect_reply(array<uint8_t, IP_MAXPACKET> &packet, int size);
    void print_username_password(uint8_t *packet, int size);
    void implement_nfq();
    static int process_nfq_package(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
    void reply_dns(unsigned char *payload, int len, int qlen);                           
    pair<string, int> get_dns_name(const unsigned char *packet, int dns_start);
    uint16_t cal_IP_checksum(struct iphdr *iph);
    uint16_t cal_TCP_checksum(struct iphdr *iph, struct udphdr *udph, int resp_mv);
    void sendUDP(char *data, int len);

};