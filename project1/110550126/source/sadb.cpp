#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(msg) / 8;
  msg.sadb_msg_pid = getpid();

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  int sockfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (sockfd < 0) {
    std::cerr << "Failed to create socket" << std::endl;
    return std::nullopt;
  }
  if (write(sockfd, &msg, sizeof(msg)) < 0) {
    std::cerr << "Failed to write to socket" << std::endl;
    return std::nullopt;
  }
  
  // Then read from socket to get SADB information
  std::span<uint8_t> key_data;
  std::span<uint8_t> encrypted_key_data;
  sadb_sa *sa;
  sadb_address *addr;
  sadb_key *key;
  sockaddr_in *src_addr;
  sockaddr_in *dst_addr;
  
  int read_size = read(sockfd, message.data(), message.size());
  std::cout << "Read size: " << read_size << std::endl;
  if (read_size < 0) {
    std::cerr << "Failed to read from socket" << std::endl;
    return std::nullopt;
  }
  sadb_msg *message_received  = (sadb_msg *)message.data();
  std::cout << "Message type: " << message_received->sadb_msg_type << std::endl;
  std::cout << "Message length: " << message_received->sadb_msg_len << std::endl;
  std::cout << "Message pid: " << message_received->sadb_msg_pid << std::endl;
  std::cout << "Message sequence: " << message_received->sadb_msg_seq << std::endl; // if == 0 then last message
  std::cout << "Message reserved: " << message_received->sadb_msg_reserved << std::endl;
  
  
  int current_offset = sizeof(sadb_msg);
  sadb_ext *ext = (sadb_ext *)(message_received + 1);

  while(current_offset < read_size){
    // std::cout << "Ext type: " << ext->sadb_ext_type << std::endl;
    switch(ext->sadb_ext_type){
      case SADB_EXT_SA: // 1
        sa = (sadb_sa *)ext;
        std::cout << "SA SPI: " << std::hex << htonl(sa->sadb_sa_spi) << std::dec << std::endl;
        std::cout << "Auth alg: " << (unsigned)sa->sadb_sa_auth << std::endl;
        std::cout << "Enc alg: " << (unsigned)sa->sadb_sa_encrypt << std::endl;
        break;
      case SADB_EXT_ADDRESS_SRC: // 5
        addr = (sadb_address *)ext;
        src_addr = (sockaddr_in *)(addr + 1);
        std::cout << "Source address: " << inet_ntoa(src_addr->sin_addr) << std::endl;
        break;
      case SADB_EXT_ADDRESS_DST: // 6
        addr = (sadb_address *)ext;
        dst_addr = (sockaddr_in *)(addr + 1);
        std::cout << "Destination address: " << inet_ntoa(dst_addr->sin_addr) << std::endl;
        break;
      case SADB_EXT_KEY_AUTH: // 8
        key = (sadb_key *)ext;
        std::cout << "Key length: " << key->sadb_key_bits << std::endl;
        key_data = std::span<uint8_t>((uint8_t *)(key + 1), key->sadb_key_bits / 8);
        std::cout << "Key data: ";
        for (const auto& byte : key_data) {
          std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }std::cout << std::endl;
        break;
      case SADB_EXT_KEY_ENCRYPT:
        key = (sadb_key *)ext;
        std::cout << "Encrypted key length: " << key->sadb_key_bits << std::endl;
        encrypted_key_data = std::span<uint8_t>((uint8_t *)(key + 1), key->sadb_key_bits / 8);
        std::cout << "Encrypted key data: ";
        for (const auto& byte : encrypted_key_data) {
          std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }std::cout << std::endl;
        break;
      default:
        break;
    }
    current_offset += ext->sadb_ext_len * 8;
    ext = reinterpret_cast<sadb_ext*>(reinterpret_cast<char*>(ext) + ext->sadb_ext_len * 8);
  }

  

  close(sockfd);
  // TODO: Set size to number of bytes in response message
  int size = sizeof(message);
  std::cout << "SADB message size: " << size << std::endl;
  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    config.spi = sa->sadb_sa_spi;
    config.aalg = std::make_unique<ESP_AALG>((unsigned)sa->sadb_sa_auth, key_data);
    if((unsigned)sa->sadb_sa_encrypt == SADB_EALG_NONE){
      // No enc algorithm:
      config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    }
    else{
      // Have enc algorithm:
      config.ealg = std::make_unique<ESP_EALG>((unsigned)sa->sadb_sa_encrypt, std::span<uint8_t>{key_data}.subspan(16));
    }
    config.local = ipToString(dst_addr->sin_addr.s_addr);
    config.remote = ipToString(src_addr->sin_addr.s_addr);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
