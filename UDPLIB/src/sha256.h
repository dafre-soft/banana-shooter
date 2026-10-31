/* Минимальная реализация SHA-256 (общая для udplib и prepatcher, C/C++). */
#ifndef UDPLIB_SHA256_H_
#define UDPLIB_SHA256_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t total;    /* всего байт передано через update                   */
    uint8_t  buffer[64];
    size_t   datalen;  /* байт в текущем незавершённом блоке                */
} udplib_sha256_ctx;

void udplib_sha256_init(udplib_sha256_ctx* ctx);
void udplib_sha256_update(udplib_sha256_ctx* ctx, const void* data, size_t len);
void udplib_sha256_final(udplib_sha256_ctx* ctx, uint8_t out[32]);
/* convenience: sha256 строка -> hex (64 символа + terminating NUL) */
void udplib_sha256_hex(const char* text, char out_hex[65]);
/* постоянный по времени срав hex-строк (для проверки пароля) */
int udplib_secure_equals(const char* a, const char* b);

#ifdef __cplusplus
}
#endif

#endif /* UDPLIB_SHA256_H_ */
