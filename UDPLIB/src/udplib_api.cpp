/* ============================================================
 *  udplib_api.cpp - экспорт C-функций нативной библиотеки.
 *  Вызывается из Unity (C# [DllImport "udplib"]) и из тестового
 *  хоста. Реализация опирается на udplib::Server.
 * ============================================================ */
#include "udplib_native.h"
#include "udplib_server.h"

#include <cstdio>
#include <cstring>

static int g_active = 0;

extern "C" {

UDPLIB_API int udplib_init(unsigned udp_port, unsigned tcp_port) {
    if (g_active) return 1;                        /* идемпотентно */
    uint16_t u = (udp_port == 0 || udp_port > 65535u) ? (uint16_t)UDPLIB_UDP_PORT : (uint16_t)udp_port;
    uint16_t t = (tcp_port  == 0 || tcp_port  > 65535u) ? (uint16_t)UDPLIB_TCP_PORT : (uint16_t)tcp_port;
    if (!udplib::Server::Instance().Start(u, t)) return 0;
    g_active = 1;
    printf("[udplib] active: %s, %s, udp=%u tcp=%u\n",
           UDPLIB_VERSION_TEXT, UDPLIB_BUILD_TEXT, (unsigned)u, (unsigned)t);
    return 1;
}

UDPLIB_API void udplib_shutdown(void) {
    if (!g_active) return;
    udplib::Server::Instance().Stop();
    g_active = 0;
}

UDPLIB_API int udplib_is_active(void) {
    return udplib::Server::Instance().Running() ? 1 : 0;
}

UDPLIB_API const char* udplib_version_string(void) { return UDPLIB_VERSION_TEXT; }
UDPLIB_API const char* udplib_build_string(void)   { return UDPLIB_BUILD_TEXT; }

UDPLIB_API const char* udplib_full_banner(void) {
    static char banner[256];
    snprintf(banner, sizeof(banner), "%s\n%s", UDPLIB_VERSION_TEXT, UDPLIB_BUILD_TEXT);
    return banner;
}

UDPLIB_API void udplib_get_console_text(char* out, int out_len) {
    if (!out || out_len <= 0) return;
    snprintf(out, (size_t)out_len, "%s\n%s",
             UDPLIB_VERSION_TEXT, UDPLIB_BUILD_TEXT);
    if (!g_active) {
        strncat(out, "\n(not loaded)", (size_t)(out_len - (int)strlen(out) - 1));
    }
}

UDPLIB_API int udplib_check_password(const char* password_utf8) {
    if (!password_utf8) return 0;
    return udplib::PasswordOk(password_utf8) ? 1 : 0;
}

UDPLIB_API void udplib_broadcast_event(const char* text_utf8) {
    if (!text_utf8) return;
    udplib::Server::Instance().BroadcastEvent(text_utf8);
}

UDPLIB_API int udplib_udp_client_count(void) {
    return udplib::Server::Instance().ClientCount();
}

}  /* extern "C" */

/* Конструктор образа: библиотека сама поднимает сервер при загрузке
   (LD_PRELOAD / LoadLibrary без managed-хостинга тоже работают).
   Порты можно переопределить переменными окружения. */
#if !defined(UDPLIB_NO_AUTOINIT)
#include <cstdlib>

static unsigned env_port(const char* name, unsigned dflt) {
    const char* v = getenv(name);
    if (!v || !*v) return dflt;
    long p = strtol(v, nullptr, 10);
    if (p <= 0 || p > 65535L) return dflt;
    return (unsigned)p;
}

#if defined(_WIN32)
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        udplib_init(env_port("UDPLIB_UDP_PORT", UDPLIB_UDP_PORT),
                    env_port("UDPLIB_TCP_PORT", UDPLIB_TCP_PORT));
    } else if (reason == DLL_PROCESS_DETACH) {
        udplib_shutdown();
    }
    return TRUE;
}
#else
__attribute__((constructor)) static void udplib_autoload(void) {
    udplib_init(env_port("UDPLIB_UDP_PORT", UDPLIB_UDP_PORT),
                env_port("UDPLIB_TCP_PORT", UDPLIB_TCP_PORT));
}
__attribute__((destructor)) static void udplib_unload(void) {
    udplib_shutdown();
}
#endif
#endif  /* UDPLIB_NO_AUTOINIT */
