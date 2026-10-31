/* ============================================================
 *  prepatcher/main.c - утилита пред-патчинга бинарника игры.
 *
 *  Назначение:
 *    1) посчитать SHA-256 файла (целостность дистрибутива);
 *    2) найти в ELF/PE-файле сигнатуру и заменить её на новую
 *       (например, подменить строку версии или magic пакета),
 *       ТОЛЬКО если длины совпадают (in-place патч без сдвига);
 *    3) проверить, что файл уже запатчен (идемпотентность).
 *
 *  Использование:
 *    prepatcher hash <file>
 *    prepatcher patch <file> <old-hex-pattern> <new-hex-pattern> [--dry]
 *      паттерны - hex байты без префикса, чётной длины; длина обязана совпасть
 *    prepatcher verify <file> <hex-pattern>
 * ============================================================ */
#include "../src/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK (64 * 1024)

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* hex-строка -> байты; возвращает длину или -1 при ошибке */
static long hexdecode(const char* hex, unsigned char* out, size_t out_cap) {
    size_t n = strlen(hex);
    if (n % 2 != 0) return -1;
    if (n / 2 > out_cap) return -1;
    for (size_t i = 0; i < n / 2; ++i) {
        int hi = hexval(hex[2*i]), lo = hexval(hex[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return (long)(n / 2);
}

static FILE* open_or_die(const char* path, const char* mode) {
    FILE* f = fopen(path, mode);
    if (!f) { perror(path); exit(1); }
    return f;
}

static int cmd_hash(const char* path) {
    FILE* f = open_or_die(path, "rb");
    udplib_sha256_ctx ctx;
    unsigned char buf[CHUNK];
    size_t r;
    char hex[65];
    uint8_t digest[32];
    int i;
    udplib_sha256_init(&ctx);
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
        udplib_sha256_update(&ctx, buf, r);
    if (ferror(f)) { perror("read"); fclose(f); return 1; }
    fclose(f);
    udplib_sha256_final(&ctx, digest);
    for (i = 0; i < 32; ++i) sprintf(hex + i*2, "%02x", digest[i]);
    printf("%s  %s\n", hex, path);
    return 0;
}

/* Поиск подпоследовательности; возвращает смещение или -1. count==0 -> все. */
static long find_all(unsigned char* data, size_t len,
                     const unsigned char* pat, size_t plen, long count) {
    long found = 0;
    if (plen == 0 || plen > len) return -1;
    for (size_t i = 0; i + plen <= len; ++i) {
        if (memcmp(data + i, pat, plen) == 0) {
            if (count == 1) return (long)i;
            ++found;
        }
    }
    return count == 0 ? found : -1;
}

static int cmd_patch(const char* path, const char* oldhex, const char* newhex, int dry) {
    unsigned char oldb[512], newb[512];
    long oldlen = hexdecode(oldhex, oldb, sizeof(oldb));
    long newlen = hexdecode(newhex, newb, sizeof(newb));
    FILE* f;
    long size;
    unsigned char* data;
    long off;

    if (oldlen < 0 || newlen < 0) { fprintf(stderr, "bad hex pattern\n"); return 2; }
    if (oldlen != newlen) { fprintf(stderr, "lengths must match (in-place patch)\n"); return 2; }
    if (oldlen == 0) { fprintf(stderr, "empty pattern\n"); return 2; }

    f = open_or_die(path, "rb");
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0 || (size_t)size > 256u * 1024u * 1024u) {
        fprintf(stderr, "file too big or empty: %ld\n", size);
        fclose(f); return 1;
    }
    data = malloc((size_t)size);
    if (!data) { fclose(f); return 1; }
    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        perror("read"); free(data); fclose(f); return 1;
    }
    fclose(f);

    off = find_all(data, (size_t)size, oldb, (size_t)oldlen, 1);
    if (off < 0) {
        /* возможно уже запатчен */
        if (find_all(data, (size_t)size, newb, (size_t)newlen, 1) >= 0) {
            printf("already patched (%s)\n", path);
            free(data); return 0;
        }
        printf("PATTERN NOT FOUND: %s\n", oldhex);
        free(data); return 3;
    }
    printf("patch @%ld: %s -> %s%s\n", off, oldhex, newhex, dry ? " [dry-run]" : "");
    if (dry) { free(data); return 0; }

    memcpy(data + off, newb, (size_t)newlen);
    f = fopen(path, "wb");
    if (!f) { perror(path); free(data); return 1; }
    if (fwrite(data, 1, (size_t)size, f) != (size_t)size) {
        perror("write"); free(data); fclose(f); return 1;
    }
    fclose(f);
    free(data);
    printf("patched OK: %s\n", path);
    return 0;
}

static int cmd_verify(const char* path, const char* hexpat) {
    unsigned char pat[512];
    long plen = hexdecode(hexpat, pat, sizeof(pat));
    FILE* f;
    long size;
    unsigned char* data;
    int rc;
    if (plen <= 0) { fprintf(stderr, "bad pattern\n"); return 2; }
    f = open_or_die(path, "rb");
    fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
    data = malloc((size_t)size);
    if (!data) { fclose(f); return 1; }
    if (size > 0 && fread(data, 1, (size_t)size, f) != (size_t)size) {
        perror("read"); free(data); fclose(f); return 1;
    }
    fclose(f);
    rc = find_all(data, (size_t)size, pat, (size_t)plen, 1) >= 0 ? 0 : 3;
    printf("%s: pattern %s %s\n", path, hexpat, rc == 0 ? "FOUND" : "MISSING");
    free(data);
    return rc;
}

static void usage(void) {
    fprintf(stderr,
        "usage:\n"
        "  prepatcher hash   <file>\n"
        "  prepatcher patch  <file> <old-hex> <new-hex> [--dry]\n"
        "  prepatcher verify <file> <hex>\n");
}

int main(int argc, char** argv) {
    if (argc < 3) { usage(); return 2; }
    if (strcmp(argv[1], "hash") == 0)
        return cmd_hash(argv[2]);
    if (strcmp(argv[1], "patch") == 0) {
        if (argc < 5) { usage(); return 2; }
        return cmd_patch(argv[2], argv[3], argv[4], argc > 5 && strcmp(argv[5], "--dry") == 0);
    }
    if (strcmp(argv[1], "verify") == 0) {
        if (argc < 4) { usage(); return 2; }
        return cmd_verify(argv[2], argv[3]);
    }
    usage();
    return 2;
}
