#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <map>
#include <net/if.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>

#include <vector>
#include <array>
#include <string>
#include <string.h>           
#include <unistd.h>           

#include <sys/ioctl.h>        
#include <bits/ioctls.h>      
#include <net/if.h>
#include <linux/if_packet.h>  
#include <linux/if_arp.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <chrono>
#include <ctime>
#include <linux/tcp.h>
#include <thread>
#include <signal.h>
#define MACAddress array<uint8_t, 6>
#define IPAddress array<uint8_t, 4>
using namespace std;

struct arp_pkg {
    uint16_t HardwareType;
    uint16_t ProtocolType;
    uint8_t HardwareLength;
    uint8_t ProtocolLength;
    uint16_t Operation; 
    MACAddress SenderHardwareAddress;
    IPAddress SenderProtocolAddress;
    MACAddress TargetHardwareAddress;
    IPAddress TargetProtocolAddress;
};

struct dns_pkg{
    uint16_t ID;
    uint16_t Flags;
    uint16_t num_of_question;
    uint16_t num_of_answer;
    uint16_t num_of_authority;
    uint16_t num_of_additional;
};

struct __attribute__((packed, aligned(2))) response_header {
  uint16_t name;
  uint16_t type;
  uint16_t class_; // class
  uint32_t ttl;
  uint16_t len;
};

class AttackerInfo{
public:
    const char *route_table_path = "/proc/net/route";
    char *interface;
    MACAddress src_mac;
    struct sockaddr_in src_ip;
    struct sockaddr_in netmask;
    struct sockaddr_in gateway_ip;
    struct sockaddr_ll device;

    AttackerInfo(char *interface);
    AttackerInfo(){};
    void get_attacker_info();
    void get_defaultGateway();
    void print_attacker_info();
};

class Attacker{
public:
    char *interface;
    AttackerInfo attacker_info;
    int sockfd;    
    struct sockaddr_ll device;
    IPAddress gateway_ip;
    MACAddress gateway_mac;
    map<IPAddress, MACAddress> victims;

    Attacker(char *interface);
    void print_avaliable_devices();
    void print_victim(IPAddress ip, MACAddress mac);
    void arp_spoof();
    void scan();
    arp_pkg make_arp(uint16_t operation, IPAddress sender_ip, MACAddress sender_mac, IPAddress target_ip, MACAddress target_mac);
    void send_arp(arp_pkg arp, MACAddress dest_mac);
    void receive_arp();
};