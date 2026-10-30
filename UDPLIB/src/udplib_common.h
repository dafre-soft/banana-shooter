/* ============================================================
 *  UDPLIB - общие определения (протокол, пароль, версии)
 *  Используется нативной частью библиотеки (C++) и prepatcher'ом.
 * ============================================================ */
#ifndef UDPLIB_COMMON_H_
#define UDPLIB_COMMON_H_

#include <stdint.h>
#include <stddef.h>

/* magic в начале каждого пакета чистой UDP-фазы */
#define UDPLIB_MAGIC    0x504C4455u   /* bytes 'U','D','P','L' little-endian */
#define UDPLIB_PROTOCOL 1u

/* ---------- встроенный UDP-сервер для чистых UDP-клиентов ---------- */
#ifndef UDPLIB_UDP_PORT
#define UDPLIB_UDP_PORT 27777u
#endif
#ifndef UDPLIB_MAX_CLIENTS
#define UDPLIB_MAX_CLIENTS 8
#endif

/* Формат пакета:
 *   [0..3]   uint32  magic  (UDPLIB_MAGIC)
 *   [4]      uint8   type   (UdplibUdpType)
 *   [5]      uint8   flags
 *   [6..7]   uint16  seq    (little endian)
 *   [8..]    тело, зависит от типа
 */
#define UDPLIB_UDP_HEADER_SIZE 8

enum UdplibUdpType {
    UDPLIB_UDP_PING      = 1,  /* C->S проверка живости                 */
    UDPLIB_UDP_PONG      = 2,  /* S->C ответ на ping                    */
    UDPLIB_UDP_HANDSHAKE = 3,  /* C->S hello + имя клиента (utf-8)      */
    UDPLIB_UDP_AUTH      = 4,  /* C->S авторизация паролем (utf-8)      */
    UDPLIB_UDP_COMMAND   = 5,  /* C->S консольная команда (нужен вход)  */
    UDPLIB_UDP_STATUS    = 6,  /* S->C JSON-статус борта                */
    UDPLIB_UDP_ACK       = 7,  /* S->C подтверждение/результат команды  */
    UDPLIB_UDP_ERROR     = 8,  /* S->C текст ошибки                     */
    UDPLIB_UDP_EVENT     = 9   /* S->C событие из игры                  */
};

/* TCP-порт текстового интерфейса (telnet-подобный), для совместимости */
#ifndef UDPLIB_TCP_PORT
#define UDPLIB_TCP_PORT 27778u
#endif

/* длина hex-строки SHA-256 */
#define UDPLIB_SHA256_HEX_LEN 64

/* ---------- значения по умолчанию (переопределяются -D при билде) ------ */
#ifndef UDPLIB_VERSION_MAJOR
#define UDPLIB_VERSION_MAJOR 1
#endif
#ifndef UDPLIB_VERSION_MINOR
#define UDPLIB_VERSION_MINOR 0
#endif
#ifndef UDPLIB_VERSION_PATCH
#define UDPLIB_VERSION_PATCH 0
#endif
#ifndef UDPLIB_BUILD_NUMBER
#define UDPLIB_BUILD_NUMBER 1
#endif
#ifndef UDPLIB_BUILD_DATE
#define UDPLIB_BUILD_DATE "unknown"
#endif
#ifndef UDPLIB_PRODUCT_NAME
#define UDPLIB_PRODUCT_NAME "UDPLIB"
#endif
/* SHA-256(пароль) в hex; пустая строка == пароль не задан (доступ запрещён) */
#ifndef UDPLIB_PASSWORD_HASH
#define UDPLIB_PASSWORD_HASH ""
#endif

#define UDPLIB_STRINGIFY_(x) #x
#define UDPLIB_STRINGIFY(x) UDPLIB_STRINGIFY_(x)

#define UDPLIB_VERSION_TEXT \
    UDPLIB_PRODUCT_NAME " V" \
    UDPLIB_STRINGIFY(UDPLIB_VERSION_MAJOR) "." \
    UDPLIB_STRINGIFY(UDPLIB_VERSION_MINOR) "." \
    UDPLIB_STRINGIFY(UDPLIB_VERSION_PATCH)

#define UDPLIB_BUILD_TEXT "Build " UDPLIB_STRINGIFY(UDPLIB_BUILD_NUMBER) \
    " from " UDPLIB_BUILD_DATE

#ifdef __cplusplus
namespace udplib {

inline const char* VersionString() { return UDPLIB_VERSION_TEXT; }
inline const char* BuildString()   { return UDPLIB_BUILD_TEXT; }

}  // namespace udplib
#endif

#endif  /* UDPLIB_COMMON_H_ */
