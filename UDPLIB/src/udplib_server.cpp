/* ============================================================
 *  udplib_server.cpp - встроенный сервер UDPLIB.
 *  Слушает UDP-порт (чистые UDP-клиенты) и TCP-порт
 *  (telnet-подобная консоль для администратора).
 *  Общий код для Windows (udplib.dll) и Linux (udplib.so).
 * ============================================================ */
#include "udplib_server.h"
#include "sha256.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#if defined(_WIN32)
  #ifndef SIO_UDP_CONNRESET   /* есть не во всех SDK - задаём константу сами */
  #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
  #endif
  static void udplib_sleep_ms(unsigned ms) { Sleep(ms); }
  static void closesock(udplib_socket_t s) { closesocket(s); }
#else
  #include <poll.h>
  #include <sys/time.h>
  #include <errno.h>
  static void udplib_sleep_ms(unsigned ms) {
    struct timespec ts; ts.tv_sec = ms / 1000; ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
  }
  static void closesock(udplib_socket_t s) { close(s); }
#endif

namespace udplib {

static bool winsock_init() {
#if defined(_WIN32)
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}
static void winsock_cleanup() {
#if defined(_WIN32)
    WSACleanup();
#endif
}

uint64_t NowMs() {
#if defined(_WIN32)
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return (u.QuadPart - 116444736000000000ULL) / 10000ULL;
#else
    struct timeval tv; gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
#endif
}

bool PasswordOk(const std::string& plain) {
    const char* want = UDPLIB_PASSWORD_HASH;
    if (want[0] == '\0') return false;          /* пароль не задан -> доступ запрещён */
    if (plain.empty())   return false;
    char hex[65];
    udplib_sha256_hex(plain.c_str(), hex);
    return udplib_secure_equals(hex, want) != 0;
}

static uint16_t rd_u16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static void wr_u16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

static bool ParseHeader(const uint8_t* data, size_t len, uint8_t& type, uint16_t& seq) {
    if (len < UDPLIB_UDP_HEADER_SIZE) return false;
    uint32_t magic = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    if (magic != UDPLIB_MAGIC) return false;
    type = data[4];
    seq  = rd_u16(data + 6);
    return true;
}

Server& Server::Instance() {
    static Server inst;
    return inst;
}

Server::~Server() { Stop(); }

bool Server::Start(uint16_t udp_port, uint16_t tcp_port) {
    if (running_.load()) return true;           /* идемпотентность */
    if (udp_port == 0) udp_port = UDPLIB_UDP_PORT;
    // tcp_port == 0 -> TCP-консоль НЕ поднимается (явный выключатель)

    if (!winsock_init()) return false;

    udp_sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock_ == UDPLIB_INVALID_SOCKET) { winsock_cleanup(); return false; }
#if defined(_WIN32)
    BOOL off = FALSE;
    DWORD bytes = 0;
    WSAIoctl(udp_sock_, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr);
#endif
    sockaddr_in ua{};
    ua.sin_family = AF_INET;
    ua.sin_addr.s_addr = htonl(INADDR_ANY);
    ua.sin_port = htons(udp_port);
    if (bind(udp_sock_, (sockaddr*)&ua, sizeof(ua)) == UDPLIB_SOCKET_ERROR) {
        closesock(udp_sock_); udp_sock_ = UDPLIB_INVALID_SOCKET; winsock_cleanup(); return false;
    }

    tcp_sock_ = UDPLIB_INVALID_SOCKET;
    if (tcp_port != 0)
    tcp_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_sock_ != UDPLIB_INVALID_SOCKET) {
        int one = 1;
        setsockopt(tcp_sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
        sockaddr_in ta{};
        ta.sin_family = AF_INET;
        ta.sin_addr.s_addr = htonl(INADDR_ANY);
        ta.sin_port = htons(tcp_port);
        if (bind(tcp_sock_, (sockaddr*)&ta, sizeof(ta)) != 0 ||
            listen(tcp_sock_, 4) != 0) {
            closesock(tcp_sock_); tcp_sock_ = UDPLIB_INVALID_SOCKET;
        }
    }

    live_udp_sock_.store(udp_sock_);
    live_tcp_sock_.store(tcp_sock_);
    running_.store(true);
    udp_thread_ = std::thread(&Server::UdpLoop, this, udp_port);
    if (tcp_sock_ != UDPLIB_INVALID_SOCKET)
        tcp_thread_ = std::thread(&Server::TcpLoop, this, tcp_port);
    return true;
}

void Server::Stop() {
    if (!running_.load()) return;
    running_.store(false);
    /* потоки читают live_*_sock_; закрываем через них, чтобы accept/select
       гарантированно получили ошибку и вышли */
    udplib_socket_t u = live_udp_sock_.exchange(UDPLIB_INVALID_SOCKET);
    udplib_socket_t t = live_tcp_sock_.exchange(UDPLIB_INVALID_SOCKET);
    if (u != UDPLIB_INVALID_SOCKET) closesock(u);
    if (t != UDPLIB_INVALID_SOCKET) {
#if !defined(_WIN32)
        shutdown(t, SHUT_RDWR);
#endif
        closesock(t);
    }
    udp_sock_ = UDPLIB_INVALID_SOCKET;
    tcp_sock_ = UDPLIB_INVALID_SOCKET;
    if (udp_thread_.joinable()) udp_thread_.join();
    if (tcp_thread_.joinable()) tcp_thread_.join();
    {
        std::lock_guard<std::mutex> lk(clients_mutex_);
        clients_.clear();
    }
    winsock_cleanup();
}

int Server::ClientCount() {
    std::lock_guard<std::mutex> lk(clients_mutex_);
    int n = 0;
    for (const UdpClient& c : clients_) if (c.active) ++n;
    return n;
}

std::string Server::StatusJson() {
    std::lock_guard<std::mutex> lk(clients_mutex_);
    std::string s = "{\"version\":\"" UDPLIB_VERSION_TEXT "\",\"build\":"
                  UDPLIB_STRINGIFY(UDPLIB_BUILD_NUMBER) ",\"clients\":[";
    bool first = true;
    for (const UdpClient& c : clients_) {
        if (!c.active) continue;
        if (!first) s += ",";
        first = false;
        s += "{\"ip\":\"" + c.ip + "\",\"port\":" + std::to_string(c.port) +
             ",\"name\":\"" + c.name + "\",\"authed\":" + (c.authed ? "true" : "false") + "}";
    }
    s += "]}";
    return s;
}

UdpClient* Server::FindClientLocked(const std::string& ip, uint16_t port) {
    for (UdpClient& c : clients_)
        if (c.active && c.ip == ip && c.port == port) return &c;
    return nullptr;
}

UdpClient* Server::TouchClient(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lk(clients_mutex_);
    if (clients_.empty()) clients_.resize(UDPLIB_MAX_CLIENTS);   /* фикс. пул слотов */
    UdpClient* c = FindClientLocked(ip, port);
    if (c) { c->last_seen_ms = NowMs(); return c; }
    for (UdpClient& nc : clients_) {
        if (!nc.active) {
            nc.active = true; nc.ip = ip; nc.port = port;
            nc.name = ""; nc.authed = false; nc.last_seen_ms = NowMs();
            return &nc;
        }
    }
    return nullptr;                                  /* нет свободных слотов */
}

void Server::ExpireClients() {
    uint64_t now = NowMs();
    std::lock_guard<std::mutex> lk(clients_mutex_);
    for (UdpClient& c : clients_)
        if (c.active && now - c.last_seen_ms > UDPLIB_CLIENT_TIMEOUT_MS)
            c.active = false;
}

void Server::SendPacket(udplib_socket_t sock, uint8_t type, uint16_t seq,
                        const std::string& body, const sockaddr_in& to) {
    std::vector<uint8_t> buf(UDPLIB_UDP_HEADER_SIZE + body.size());
    uint32_t m = UDPLIB_MAGIC;
    buf[0] = (uint8_t)m; buf[1] = (uint8_t)(m >> 8); buf[2] = (uint8_t)(m >> 16); buf[3] = (uint8_t)(m >> 24);
    buf[4] = type; buf[5] = 0;
    wr_u16(buf.data() + 6, seq);
    memcpy(buf.data() + UDPLIB_UDP_HEADER_SIZE, body.data(), body.size());
    sendto(sock, (const char*)buf.data(), (int)buf.size(), 0, (const sockaddr*)&to, sizeof(to));
}

void Server::BroadcastEvent(const std::string& text) {
    if (!running_.load() || udp_sock_ == UDPLIB_INVALID_SOCKET) return;
    ExpireClients();
    std::vector<sockaddr_in> targets;
    {
        std::lock_guard<std::mutex> lk(clients_mutex_);
        for (const UdpClient& c : clients_) {
            if (!c.active) continue;
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(c.port);
            inet_pton(AF_INET, c.ip.c_str(), &a.sin_addr);
            targets.push_back(a);
        }
    }
    const udplib_socket_t bsock = live_udp_sock_.load();
    if (bsock == UDPLIB_INVALID_SOCKET) return;
    for (const sockaddr_in& a : targets)
        SendPacket(bsock, (uint8_t)UDPLIB_UDP_EVENT, 0, text, a);
}

void Server::HandleUdpPacket(udplib_socket_t sock, const uint8_t* data, size_t len, const sockaddr_in& from) {
    uint8_t type; uint16_t seq;
    if (!ParseHeader(data, len, type, seq)) return;      /* не наш пакет - молчим */

    char ipbuf[64] = {0};
    inet_ntop(AF_INET, &from.sin_addr, ipbuf, sizeof(ipbuf));
    uint16_t sport = ntohs(from.sin_port);
    std::string body((const char*)data + UDPLIB_UDP_HEADER_SIZE,
                     len - UDPLIB_UDP_HEADER_SIZE);

    switch (type) {
    case UDPLIB_UDP_PING:
        TouchClient(ipbuf, sport);
        SendPacket(sock, (uint8_t)UDPLIB_UDP_PONG, seq, "", from);
        return;

    case UDPLIB_UDP_HANDSHAKE: {
        UdpClient* c = TouchClient(ipbuf, sport);
        if (!c) { SendPacket(sock, (uint8_t)UDPLIB_UDP_ERROR, seq, "server full", from); return; }
        std::string reply = UDPLIB_VERSION_TEXT "\n" UDPLIB_BUILD_TEXT;
        SendPacket(sock, (uint8_t)UDPLIB_UDP_ACK, seq, reply, from);
        return;
    }

    case UDPLIB_UDP_AUTH: {
        UdpClient* c = TouchClient(ipbuf, sport);
        if (!c) { SendPacket(sock, (uint8_t)UDPLIB_UDP_ERROR, seq, "server full", from); return; }
        if (PasswordOk(body)) {
            c->authed = true;
            std::string name = body;   /* формат AUTH: "password\nclient_name" */
            size_t nl = name.find('\n');
            if (nl != std::string::npos) name = name.substr(nl + 1);
            if (!name.empty()) c->name = name;
            SendPacket(sock, (uint8_t)UDPLIB_UDP_ACK, seq, "OK authed", from);
        } else {
            c->authed = false;
            SendPacket(sock, (uint8_t)UDPLIB_UDP_ERROR, seq, "invalid password", from);
        }
        return;
    }

    case UDPLIB_UDP_STATUS: {
        ExpireClients();
        UdpClient* c = TouchClient(ipbuf, sport);
        if (!c || !c->authed) {
            SendPacket(sock, (uint8_t)UDPLIB_UDP_ERROR, seq, "unauthorized: auth required", from);
            return;
        }
        SendPacket(sock, (uint8_t)UDPLIB_UDP_STATUS, seq, StatusJson(), from);
        return;
    }

    case UDPLIB_UDP_COMMAND: {
        ExpireClients();
        UdpClient* c = TouchClient(ipbuf, sport);
        if (!c || !c->authed) {
            SendPacket(sock, (uint8_t)UDPLIB_UDP_ERROR, seq, "unauthorized: auth required", from);
            return;
        }
        std::string reply;
        bool dummy_authed = true;
        HandleTcpLine(body, std::string(ipbuf) + ":" + std::to_string(sport), dummy_authed, reply);
        SendPacket(sock, (uint8_t)UDPLIB_UDP_ACK, seq, reply, from);
        return;
    }

    default:
        SendPacket(sock, (uint8_t)UDPLIB_UDP_ERROR, seq, "unknown packet type", from);
    }
}

void Server::UdpLoop(uint16_t /*port*/) {
    uint64_t next_expire = NowMs() + 1000;
    while (running_.load()) {
        const udplib_socket_t sock = live_udp_sock_.load();
        if (sock == UDPLIB_INVALID_SOCKET) { udplib_sleep_ms(20); continue; }
        fd_set rf; FD_ZERO(&rf); FD_SET(sock, &rf);
        timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;   /* 100 мс квант */
        int r = select((int)sock + 1, &rf, nullptr, nullptr, &tv);
        if (r > 0 && FD_ISSET(sock, &rf)) {
            if (!running_.load()) break;
            uint8_t buf[2048];
            sockaddr_in from{};
            socklen_t fl = sizeof(from);
            int n = recvfrom(sock, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
            if (n > 0 && running_.load()) HandleUdpPacket(sock, buf, (size_t)n, from);
        }
        uint64_t now = NowMs();
        if (now >= next_expire) { ExpireClients(); next_expire = now + 1000; }
    }
}

void Server::TcpLoop(uint16_t /*port*/) {
    while (running_.load()) {
        const udplib_socket_t lsock = live_tcp_sock_.load();
        if (lsock == UDPLIB_INVALID_SOCKET) break;
        fd_set rf; FD_ZERO(&rf); FD_SET(lsock, &rf);
        timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;
        if (select((int)lsock + 1, &rf, nullptr, nullptr, &tv) <= 0) continue;
        if (!running_.load()) break;
        udplib_socket_t cs = accept(lsock, nullptr, nullptr);
        if (cs == UDPLIB_INVALID_SOCKET) continue;
        char peer[64] = {0};
        printf("[udplib] tcp admin connection from %s\n", peer);
        const char* hello = UDPLIB_PRODUCT_NAME " console. Type HELP.\n";
        send(cs, hello, (int)strlen(hello), 0);

        std::string acc;
        bool authed = false;
        char rb[512];
        while (running_.load()) {
            int n = recv(cs, rb, sizeof(rb), 0);
            if (n <= 0) break;
            acc.append(rb, (size_t)n);
            size_t pos;
            while ((pos = acc.find('\n')) != std::string::npos) {
                std::string line = acc.substr(0, pos);
                acc.erase(0, pos + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                std::string reply;
                HandleTcpLine(line, "tcp", authed, reply);
                reply += "\n";
                if (send(cs, reply.data(), (int)reply.size(), 0) <= 0) { running_.load(); }
                if (line == "quit" || line == "exit") { closesock(cs); return; }
            }
        }
        closesock(cs);
    }
}

void Server::HandleTcpLine(const std::string& line, const std::string& peer,
                           bool& authed, std::string& reply) {
    auto starts = [&](const char* p) { return line.compare(0, strlen(p), p) == 0; };
    if (line.empty()) { reply = ""; return; }

    if (starts("auth ")) {
        std::string pass = line.substr(5);
        if (PasswordOk(pass)) { authed = true; reply = "OK authenticated"; }
        else reply = "DENIED invalid password";
        printf("[udplib] tcp auth from %s: %s\n", peer.c_str(), authed ? "ok" : "denied");
        return;
    }
    if (starts("ping")) { reply = "pong"; return; }
    if (starts("help")) {
        reply = "commands: ping | auth <password> | udplib | status | version | "
                "say <text> | quit";
        return;
    }
    if (starts("udplib") || starts("version")) {
        reply = UDPLIB_VERSION_TEXT "\n" UDPLIB_BUILD_TEXT;
        return;
    }
    if (!authed) { reply = "unauthorized: use 'auth <password>' first"; return; }
    if (starts("status")) { reply = StatusJson(); return; }
    if (starts("say ")) {
        BroadcastEvent(line.substr(5));
        reply = "event broadcasted";
        return;
    }
    if (starts("quit") || starts("exit")) { reply = "bye"; return; }
    reply = "unknown command";
}

}  // namespace udplib
