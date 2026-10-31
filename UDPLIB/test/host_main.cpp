// ============================================================
//  host_main.cpp - стенд "хост" для тестов UDPLIB.
//  Эмулирует бор (игру): поднимает нативную библиотеку, выводит
//  баннер как консольная команда "udplib", крутится до SIGINT/SIGTERM
//  или до таймаута, заданного аргументом (--seconds N).
//
//  Использование:
//    host_main [--udp PORT] [--tcp PORT] [--seconds N] [--banner]
// ============================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <chrono>
#include <thread>
#include <atomic>

#include "udplib_native.h"

static std::atomic<bool> g_stop{false};

static void OnSignal(int) { g_stop.store(true); }

int main(int argc, char** argv) {
    unsigned udp = 0, tcp = UDPLIB_TCP_PORT;  // udp 0 -> дефолт; tcp 0 -> выключить консоль
    int seconds = 30;
    bool show_banner = true;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--udp") && i + 1 < argc)      udp = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--tcp") && i + 1 < argc) tcp = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--seconds") && i + 1 < argc) seconds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--banner"))              show_banner = true;
        else if (!strcmp(argv[i], "--no-banner"))           show_banner = false;
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }

    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);

    // Стенд компилируется с UDPLIB_NO_AUTOINIT, поэтому сервер поднимается
    // явным вызовом. tcp_port==0 -> "не поднимать TCP-консоль" обрабатывается
    // внутри Server::Start (0 допустим и означает "выключить").
    unsigned req_udp = udp, req_tcp = tcp;
    if (udplib_init(udp, tcp) != 1) {
        // порт уже занят автоинициализацией/предыдущим прогоном?
        if (udplib_is_active()) {
            printf("[host] already active via autoinit\n");
        } else {
            fprintf(stderr, "[host] udplib_init FAILED (udp=%u tcp=%u)\n", udp, tcp);
            return 1;
        }
    }
    (void)req_udp; (void)req_tcp;
    printf("[host] udplib active=%d\n", udplib_is_active());

    // Индикатор присутствия библиотеки: ровно то, что печатает
    // консольная команда "udplib" в игре.
    if (show_banner) {
        char banner[512];
        const char* b = udplib_full_banner();
        snprintf(banner, sizeof(banner), "%s", b ? b : "(no banner)");
        printf("COMMAND: udplib\n%s\n", banner);
        fflush(stdout);
    }

    // Имитация игровых событий для подписчиков EVENT:
    // первые секунды крутим тики часто (250мс), чтобы тестовый
    // клиент гарантированно успел поймать рассылку.
    for (int t = 0; t < seconds * 4 && !g_stop.load(); ++t) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (t % 4 == 0) {
            char ev[96];
            snprintf(ev, sizeof(ev), "{\"type\":\"tick\",\"t\":%d,\"clients\":%d}",
                     t / 4, udplib_udp_client_count());
            udplib_broadcast_event(ev);
        }
    }

    printf("[host] clients at exit: %d\n", udplib_udp_client_count());
    udplib_shutdown();
    printf("[host] shutdown done\n");
    return 0;
}
