// ============================================================
//  udp_client.cpp - "чистый" UDP-клиент для проверки UDPLIB.
//  Работает по протоколу из udplib_common.h без каких-либо
//  зависимостей от библиотеки хоста (только заголовок протокола).
//
//  Использование:
//    udp_client <host> <password> [--udp PORT] [--cmd "COMMAND"]
//
//  Шаги: PING->PONG, HANDSHAKE, AUTH(password), опционально COMMAND,
//  затем слушает EVENT-рассылку несколько секунд.
//  Код возврата 0 = все проверки пройдены.
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define CLOSESOCK closesocket
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  typedef int sock_t;
  #define CLOSESOCK close
#endif

#include "udplib_common.h"

static void PutU16(uint8_t* p, uint16_t v) { p[0] = v & 0xFF; p[1] = v >> 8; }
static uint16_t GetU16(const uint8_t* p)   { return (uint16_t)(p[0] | (p[1] << 8)); }

static std::string MakePacket(uint8_t type, uint16_t seq, const std::string& body) {
    std::string pkt;
    pkt.resize(UDPLIB_UDP_HEADER_SIZE + body.size());
    uint8_t* p = reinterpret_cast<uint8_t*>(&pkt[0]);
    uint32_t m = UDPLIB_MAGIC;
    memcpy(p, &m, 4);              // little-endian magic
    p[4] = type;
    p[5] = 0;                      // flags
    PutU16(p + 6, seq);
    memcpy(p + UDPLIB_UDP_HEADER_SIZE, body.data(), body.size());
    return pkt;
}

// Ждёт пакет нужного типа с таймаутом. Возвращает тело (после заголовка).
static bool RecvType(sock_t s, uint8_t want, uint16_t want_seq,
                     std::string* out_body, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    if (select(s + 1, &rfds, nullptr, nullptr, &tv) <= 0) return false;

    uint8_t buf[2048];
    ssize_t n = recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
    if (n < (ssize_t)UDPLIB_UDP_HEADER_SIZE) return false;
    uint32_t m;
    memcpy(&m, buf, 4);
    if (m != UDPLIB_MAGIC) return false;
    if (buf[4] != want) {
        fprintf(stderr, "[client] got type=%u seq=%u, wanted type=%u\n",
                buf[4], GetU16(buf + 6), want);
        // сохраняем ERROR-текст для диагностики
        if (out_body && buf[4] == UDPLIB_UDP_ERROR)
            out_body->assign(reinterpret_cast<char*>(buf) + UDPLIB_UDP_HEADER_SIZE,
                             (size_t)n - UDPLIB_UDP_HEADER_SIZE);
        return false;
    }
    if (want_seq && GetU16(buf + 6) != want_seq) return false;
    if (out_body)
        out_body->assign(reinterpret_cast<char*>(buf) + UDPLIB_UDP_HEADER_SIZE,
                         (size_t)n - UDPLIB_UDP_HEADER_SIZE);
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <host> <password> [--udp PORT] [--cmd \"TEXT\"]\n", argv[0]);
        return 2;
    }
    const char* host = argv[1];
    const char* password = argv[2];
    unsigned port = UDPLIB_UDP_PORT;
    const char* command = nullptr;
    for (int i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--udp") && i + 1 < argc) port = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cmd") && i + 1 < argc) command = argv[++i];
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { perror("WSAStartup"); return 1; }
#endif

    sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == (sock_t)-1) { perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    int rc = 1;

    auto run = [&]() -> bool {
        std::string body;

        // --- 1) PING
        auto ping = MakePacket(UDPLIB_UDP_PING, 1, "hi");
        sendto(s, ping.data(), ping.size(), 0, (sockaddr*)&addr, sizeof(addr));
        if (!RecvType(s, UDPLIB_UDP_PONG, 1, &body, 2000)) {
            fprintf(stderr, "[client] PING/PONG FAILED\n"); return false;
        }
        printf("[client] PONG ok (body='%s')\n", body.c_str());

        // --- 2) HANDSHAKE
        auto hs = MakePacket(UDPLIB_UDP_HANDSHAKE, 2, "test-client");
        sendto(s, hs.data(), hs.size(), 0, (sockaddr*)&addr, sizeof(addr));
        if (!RecvType(s, UDPLIB_UDP_ACK, 2, &body, 2000)) {
            fprintf(stderr, "[client] HANDSHAKE FAILED (%s)\n", body.c_str()); return false;
        }
        printf("[client] HANDSHAKE ok (ack='%s')\n", body.c_str());

        // --- 3) AUTH (password)
        auto auth = MakePacket(UDPLIB_UDP_AUTH, 3, password);
        sendto(s, auth.data(), auth.size(), 0, (sockaddr*)&addr, sizeof(addr));
        if (!RecvType(s, UDPLIB_UDP_ACK, 3, &body, 2000)) {
            fprintf(stderr, "[client] AUTH FAILED (%s)\n", body.c_str()); return false;
        }
        printf("[client] AUTH ok (ack='%s')\n", body.c_str());

        // --- 4) STATUS
        auto st = MakePacket(UDPLIB_UDP_STATUS, 4, "");
        sendto(s, st.data(), st.size(), 0, (sockaddr*)&addr, sizeof(addr));
        if (!RecvType(s, UDPLIB_UDP_STATUS, 4, &body, 2000)) {
            fprintf(stderr, "[client] STATUS FAILED (%s)\n", body.c_str()); return false;
        }
        printf("[client] STATUS ok: %s\n", body.c_str());

        // --- 5) COMMAND (optional)
        if (command) {
            auto cmd = MakePacket(UDPLIB_UDP_COMMAND, 5, command);
            sendto(s, cmd.data(), cmd.size(), 0, (sockaddr*)&addr, sizeof(addr));
            body.clear();
            if (RecvType(s, UDPLIB_UDP_ACK, 5, &body, 2000))
                printf("[client] COMMAND '%s' ok: %s\n", command, body.c_str());
            else
                printf("[client] COMMAND reply: %s\n", body.c_str());
        }

        // --- 6) EVENT stream
        int events = 0;
        for (int i = 0; i < 5; ++i) {
            if (RecvType(s, UDPLIB_UDP_EVENT, 0, &body, 2500)) {
                printf("[client] EVENT: %s\n", body.c_str());
                if (++events >= 2) break;
            }
        }
        if (events == 0) printf("[client] no EVENT received (ok if host idle)\n");
        return true;
    };
    rc = run() ? 0 : 1;
done:
    CLOSESOCK(s);
#ifdef _WIN32
    WSACleanup();
#endif
    printf("[client] result=%d\n", rc);
    return rc;
}
