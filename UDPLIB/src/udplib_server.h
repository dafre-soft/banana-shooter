#ifndef UDPLIB_SERVER_H_
#define UDPLIB_SERVER_H_

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "udplib_common.h"

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET udplib_socket_t;
  #define UDPLIB_INVALID_SOCKET INVALID_SOCKET
  #define UDPLIB_SOCKET_ERROR   SOCKET_ERROR
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  typedef int udplib_socket_t;
  #define UDPLIB_INVALID_SOCKET (-1)
  #define UDPLIB_SOCKET_ERROR   (-1)
#endif

namespace udplib {

struct UdpClient {
    bool active = false;
    std::string ip;
    uint16_t port = 0;
    std::string name;
    uint64_t last_seen_ms = 0;
    bool authed = false;
};

class Server {
public:
    static Server& Instance();

    bool Start(uint16_t udp_port, uint16_t tcp_port);
    void Stop();
    bool Running() const { return running_.load(); }

    void BroadcastEvent(const std::string& text);
    int  ClientCount();
    std::string StatusJson();

private:
    Server() = default;
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void UdpLoop(uint16_t port);
    void TcpLoop(uint16_t port);
    void HandleUdpPacket(udplib_socket_t sock, const uint8_t* data, size_t len,
                         const struct sockaddr_in& from);
    void SendTo(udplib_socket_t sock, const uint8_t* buf, size_t len,
                const struct sockaddr_in& to);
    void HandleTcpLine(std::string line, const std::string& peer,
                       bool& authed, std::string& reply);

    std::atomic<bool> running_{false};
    std::thread udp_thread_, tcp_thread_;
    udplib_socket_t udp_sock_ = UDPLIB_INVALID_SOCKET;
    udplib_socket_t tcp_sock_ = UDPLIB_INVALID_SOCKET;
    std::mutex clients_mutex_;
    std::vector<UdpClient> clients_;
};

uint64_t NowMs();
bool PasswordOk(const std::string& plain);

}  // namespace udplib

#endif  /* UDPLIB_SERVER_H_ */
