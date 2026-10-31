/* ============================================================
 *  sha256.c - компиляционный модуль эталонного SHA-256 (FIPS 180-4).
 *  Реализация находится в sha256_impl.inc - она общая для
 *  udplib.so / udplib.dll и prepatcher, чтобы хэши совпадали 1:1.
 * ============================================================ */
#include "sha256.h"
#include <string.h>

#define SHA256_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_EP1(x) (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void transform(udplib_sha256_ctx* ctx, const uint8_t block[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (; i < 64; ++i)
        w[i] = SHA256_SIG1(w[i-2]) + w[i-7] + SHA256_SIG0(w[i-15]) + w[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + K[i] + w[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void udplib_sha256_init(udplib_sha256_ctx* ctx) {
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u; ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au; ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->total = 0; ctx->datalen = 0;
}

void udplib_sha256_update(udplib_sha256_ctx* ctx, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    /* total считает ВСЕ байты исходного сообщения (включая padding,
       добавленный final() через этот же update). Инкремент — до
       обработки блока, иначе длина считается неверно. */
    while (len > 0) {
        size_t take = 64 - ctx->datalen;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->datalen, p, take);
        ctx->datalen += take; p += take; len -= take;
        ctx->total += take;
        if (ctx->datalen == 64) { transform(ctx, ctx->buffer); ctx->datalen = 0; }
    }
}

void udplib_sha256_final(udplib_sha256_ctx* ctx, uint8_t out[32]) {
    uint64_t msg_bits = ctx->total * 8u;   /* длина ДО начала padding */
    static const uint8_t pad = 0x80;
    static const uint8_t zero = 0x00;
    uint8_t tail[8];
    int i;
    udplib_sha256_update(ctx, &pad, 1);
    while (ctx->datalen != 56) udplib_sha256_update(ctx, &zero, 1);
    for (i = 0; i < 8; ++i) tail[i] = (uint8_t)(msg_bits >> (56 - 8 * i));
    udplib_sha256_update(ctx, tail, 8);
    for (i = 0; i < 8; ++i) {
        out[i*4+0] = (uint8_t)(ctx->state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

static char hexchar(unsigned v) { return (char)(v < 10 ? '0' + v : 'a' + (v - 10)); }

void udplib_sha256_hex(const char* text, char out_hex[65]) {
    uint8_t digest[32];
    udplib_sha256_ctx ctx;
    int i;
    udplib_sha256_init(&ctx);
    udplib_sha256_update(&ctx, text, strlen(text));
    udplib_sha256_final(&ctx, digest);
    for (i = 0; i < 32; ++i) {
        out_hex[i*2]   = hexchar(digest[i] >> 4);
        out_hex[i*2+1] = hexchar(digest[i] & 0xF);
    }
    out_hex[64] = '\0';
}

int udplib_secure_equals(const char* a, const char* b) {
    unsigned diff = 0;
    int i;
    for (i = 0; i <= 64; ++i) {
        unsigned ca = (unsigned)(unsigned char)a[i];
        unsigned cb = (unsigned)(unsigned char)b[i];
        diff |= (ca ^ cb);
        if (ca == 0 || cb == 0) break;
    }
    return diff == 0 ? 1 : 0;
}
