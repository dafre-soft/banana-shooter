/* ============================================================
 *  udplib_native.h - публичный C-интерфейс нативной части UDPLIB.
 *
 *  Используется:
 *    - managed-модулем (C#, Assembly-CSharp) через [DllImport];
 *    - тестовым хостом (test/host_main.cpp) без Unity, чтобы
 *      проверить протокол/пароль/версию вне игры.
 * ============================================================ */
#ifndef UDPLIB_NATIVE_H_
#define UDPLIB_NATIVE_H_

#include "udplib_common.h"

#ifdef _WIN32
  #define UDPLIB_API __declspec(dllexport)
#else
  #define UDPLIB_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Инициализация библиотеки внутри процесса игры. Идемпотентна.
 * udp_port/tcp_port == 0 -> значения по умолчанию из udplib_common.h. */
UDPLIB_API int udplib_init(unsigned udp_port, unsigned tcp_port);
/* Остановить серверы и освободить ресурсы. */
UDPLIB_API void udplib_shutdown(void);
/* 1 если библиотека активна в этом процессе. */
UDPLIB_API int udplib_is_active(void);

/* Строки версии (UTF-8, статические). */
UDPLIB_API const char* udplib_version_string(void);   /* "UDPLIB V1.0.0" */
UDPLIB_API const char* udplib_build_string(void);     /* "Build 7 from 2026-10-31T..." */
UDPLIB_API const char* udplib_full_banner(void);      /* обе строки через '\n' */

/* Текст для вывода в консоль команды `udplib`. */
UDPLIB_API void udplib_get_console_text(char* out, int out_len);

/* Проверка пароля администратора (SHA-256 hex сравнение). 1 = верно. */
UDPLIB_API int udplib_check_password(const char* password_utf8);

/* Отправить событие всем чистым UDP-клиентам (например текст из консоли). */
UDPLIB_API void udplib_broadcast_event(const char* text_utf8);

/* Число активных чистых UDP-клиентов. */
UDPLIB_API int udplib_udp_client_count(void);

#ifdef __cplusplus
}
#endif

#endif /* UDPLIB_NATIVE_H_ */
