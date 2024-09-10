#include "attacker.hpp"
using namespace std;

class MITM: public Attacker{
public:
    MITM(char *interface);
    void make_device();
    void receive_reply();
    void modify_packet(array<uint8_t, IP_MAXPACKET> &packet);
    void redirect_reply(array<uint8_t, IP_MAXPACKET> &packet, int size);
    void print_username_password(uint8_t *packet, int size);
};