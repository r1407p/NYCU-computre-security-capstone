#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>

#include <arpa/inet.h>

extern bool running;

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  // addr_ll.sll_family =
  // addr_ll.sll_protocol =
  // addr_ll.sll_ifindex =
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  //   state.recvPacket = true;
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  // std::cout << "dissectIPv4" << std::endl;
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // std::cout << hdr.protocol <<" "<<hdr.saddr <<std::endl;
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote

  /*
    packet can have we send and receive 
    so we need to check if the packet is from remote or not
  */
  if (ipToString(hdr.saddr) == config.remote.c_str()) {
    this->state.recvPacket = true;
  } else {
    this->state.recvPacket = false;
    this->state.ipId = hdr.id; // only when we send packet need to update ipId
  }
  // std::cout << "recvPacket: " << this->state.recvPacket << std::endl;
  std::span<uint8_t> payload = buffer.last(buffer.size() - hdr.ihl * 4); // ihl:: ip header length in 32-bit words to 8-bit size
  if(hdr.protocol == IPPROTO_ESP){
    this->dissectESP(payload);
  } 
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  // std::cout << "dissectESP" << std::endl;
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // std::cout << "hashLength: " << hashLength << std::endl;
  // Strip hash

  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }

  // TODO:
  // Track ESP sequence number
  if (state.recvPacket == false) {
    state.espseq = ntohl(hdr.seq);
    config.spi = ntohl(hdr.spi);
  }
  // get trailer from buffer
  auto trailer = buffer.last(sizeof(ESPTrailer));
  // get payload from buffer
  auto payload = buffer.first(buffer.size() - sizeof(ESPTrailer) - (int)trailer[0]);

  // Call dissectTCP(payload) if next protocol is TCP
  if(trailer[1] == IPPROTO_TCP){
    this->dissectTCP(payload);
  }
  
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);


  // Track tcp parameters
  state.tcpseq = ntohl(hdr.seq) + payload.size();
  state.tcpackseq = ntohl(hdr.ack_seq);
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
    state.espseq++;
    state.ipId++;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

uint16_t Session::ipv4_checksum(struct iphdr iphdr) {
  struct iphdr* temp_ptr = &iphdr;
  uint16_t* iphdr_ptr = (uint16_t*)temp_ptr;
  size_t hdr_len = iphdr.ihl * 4;
  uint32_t sum = 0;

  // Calculate the checksum for the IP header
  while (hdr_len > 1) {
    sum += *iphdr_ptr++;
    hdr_len -= 2;
  }

  // if it is odd (remain 8bit)
  if (hdr_len) {
    sum += (*iphdr_ptr) & htons(0xFF00);
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ~sum;
}


int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4;
  hdr.ihl = 5;
  hdr.ttl = 64;
  hdr.id = ntohs(ntohs(state.ipId) + 1);
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(0x4000); // Don't fragment
  hdr.saddr = stringToIPv4(config.local).s_addr;
  hdr.daddr = stringToIPv4(config.remote).s_addr;
  // hdr.daddr = addr.sll_addr;
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);
  hdr.tot_len = htons(payloadLength);
  hdr.check = ipv4_checksum(hdr);

  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  // hdr.spi =
  // hdr.seq =
  hdr.spi = htonl(config.spi);
  hdr.seq = htonl(state.espseq + 1);
  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize =  (4 - ((payloadLength + sizeof(ESPTrailer)) % 4)) % 4;
  payloadLength += padSize;
  for(int i = 0; i < padSize; i++){
    endBuffer[i] = i + 1;
  }
  // ESP trailer
  // endBuffer[padSize] =
  // endBuffer[padSize + 1] =
  endBuffer[padSize] = padSize;
  endBuffer[padSize + 1] = IPPROTO_TCP;;
  payloadLength += sizeof(ESPTrailer);
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(buffer.first(payloadLength));
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}
uint16_t Session::tcp_checksum(struct tcphdr tcphdr, const std::string& payload) {
    int sum = 0;
    // Calculate the TCP pseudo-header checksum
    auto src = inet_addr(config.local.c_str());
    auto dst = inet_addr(config.remote.c_str());
    sum += (src >> 16) & 0xFFFF;
    sum += src & 0xFFFF;
    sum += (dst >> 16) & 0xFFFF;
    sum += dst & 0xFFFF;
    sum += htons(IPPROTO_TCP);

    // header and valid length
    uint16_t tcphdr_len = tcphdr.th_off * 4;
    uint16_t tcp_len = tcphdr_len + payload.size();
    sum += htons(tcp_len);
    // Create a buffer to store the TCP header and payload
    uint8_t* buf = (uint8_t*)malloc((tcphdr_len + payload.size()) * sizeof(uint8_t));
    memcpy(buf, &tcphdr, tcphdr_len);
    memcpy(buf + tcphdr_len, payload.c_str(), payload.size());
    // make it to 16 bit
    uint16_t* pl_ptr = (uint16_t*)buf;
    while (tcp_len > 1) {
      sum += *pl_ptr++;
      tcp_len -= 2;
    }

    // if it is odd (remain 8bit)
    if (tcp_len) {
      sum += (*pl_ptr) & htons(0xFF00);
    }

    while (sum >> 16) {
      sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return ~sum;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5;
  hdr.dest = htons(state.srcPort);
  hdr.source = htons(state.dstPort);
  hdr.ack_seq = htonl(state.tcpseq);
  hdr.seq = htonl(state.tcpackseq);
  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // Update TCP sequence number
  state.tcpseq += payload.size();
  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum
  hdr.check = tcp_checksum(hdr, payload);
  return payloadLength;
}
