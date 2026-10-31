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

/* ============================================================
 *  inject - "подкидывание" udplib к уже собранному бинарнику игры.
 *    Windows (PE32+): добавляем импорт udplib.dll в таблицу импорта.
 *    Linux  (ELF64) : добавляем DT_NEEDED libudplib.so в .dynamic.
 *  Обе вставки используют свободные pad-байты и НЕ меняют размер
 *  файла, поэтому операция идемпотентна; проверка - verify/hash.
 * ------------------------------------------------------------ */

static uint16_t rd16(const unsigned char* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const unsigned char* p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}
static void w32(unsigned char* p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static void w16(unsigned char* p, uint16_t v) { p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; }
static void w64(unsigned char* p, uint64_t v) { w32(p, (uint32_t)v); w32(p + 4, (uint32_t)(v >> 32)); }

static int ci_cmp(const char* a, const char* b) {
    for (; *a && *b; ++a, ++b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return ca - cb;
    }
    return *a - *b;
}

static long pe_rva2off(const unsigned char* d, long sec_off, uint16_t nsec, uint32_t rva) {
    for (uint16_t i = 0; i < nsec; ++i) {
        long s = sec_off + i * 40;
        uint32_t va  = rd32(d + s + 12);
        uint32_t vsz = rd32(d + s + 8);
        uint32_t praw = rd32(d + s + 20);
        uint32_t rsz  = rd32(d + s + 16);
        if (rva >= va && (vsz ? rva < va + vsz : rva < va + rsz))
            return (long)praw + (rva - va);
        if (rva >= va && rva < va + rsz) return (long)praw + (rva - va);
    }
    return -1;
}

static int elf_find(const unsigned char* d, long size, const char* name, long* off_out) {
    if (size < 64 || memcmp(d, "\x7F" "ELF", 4) != 0) return 0;
    if (d[4] != 2) { fprintf(stderr, "inject: only ELF64 supported\n"); return 0; }
    uint64_t phoff = rd64(d + 32);
    uint16_t phentsize = rd16(d + 54), phnum = rd16(d + 56);
    for (uint16_t i = 0; i < phnum; ++i) {
        long p = (long)(phoff + (uint64_t)i * phentsize);
        if (p + 56 > size) return 0;
        if (rd32(d + p) == 2 /*PT_DYNAMIC*/) {
            *off_out = (long)rd64(d + p + 8);   /* p_offset */
            return 1;
        }
    }
    (void)name;
    return 0;
}

static int elf64_load(const unsigned char* d, long size, uint64_t* bias_out) {
    uint64_t phoff = rd64(d + 32);
    uint16_t phes = rd16(d + 54), phn = rd16(d + 56);
    *bias_out = 0;
    for (uint16_t i = 0; i < phn; ++i) {
        long q = (long)(phoff + (uint64_t)i * phes);
        if (q + 56 > size) return -1;
        if (rd32(d + q) == 1) { *bias_out = rd64(d + q + 16) - rd64(d + q + 8); return 0; }
    }
    return -1;
}

/* находит секцию по имени; возвращает sh_offset в *off, размер в *sz */
static int elf64_find_sec(const unsigned char* d, long size, const char* name, long* off, long* sz) {
    long shoff = (long)rd64(d + 40);
    uint16_t shes = rd16(d + 58), shn = rd16(d + 60), shstrx = rd16(d + 62);
    uint64_t bias;
    long str_off;
    uint16_t i;
    if (shstrx >= shn) return -1;
    if (elf64_load(d, size, &bias) != 0) return -1;
    str_off = (long)rd64(d + shoff + (long)shstrx * shes + 24);   /* sh_offset для SHT_STRTAB */
    if (str_off <= 0 || str_off >= size) return -1;
    for (i = 0; i < shn; ++i) {
        long s = shoff + (long)i * shes;
        long ntab;
        const char* nm;
        if (s + 64 > size) return -1;
        ntab = (long)rd32(d + s);                     /* sh_name: смещение в shstrtab */
        if (ntab < 0 || str_off + ntab >= size) continue;
        nm = (const char*)d + str_off + ntab;
        if (strcmp(nm, name) == 0) { *off = (long)rd64(d + s + 24); *sz = (long)rd64(d + s + 32); return 0; }
    }
    return -1;
}

/* Инъекция DT_NEEDED в ELF64. Возможны два режима:
 *  A) in-place: строка уже есть в .dynstr (или найден нулевой pad внутри
 *     неё), плюс свободный слот (pad до DT_NULL или хвост PT_DYNAMIC) -
 *     файл НЕ меняет размер;
 *  B) growth: строки нет и pad'а нет - добавляем новую PT_LOAD-сегмент
 *     в конец файла (.dynstr + расширенная .dynamic со старыми entry +
 *     новый DT_NEEDED + DT_NULL). e_phnum растёт на 1 (для этого в конце
 *     сегмента заголовков резервируется один NULL-слот); если его нет -
 *     используется расширение таблицы сегментов с сдвигом данных и
 *     пересчётом всех файловых смещений. */
static int elf_add_dt_needed(const char* path, unsigned char** pdata, long* psize,
                             const char* libname, int dry) {
    unsigned char* data = *pdata;
    long size = *psize;
    long dyn = 0, dynsz = 0;
    long p, last_entry = -1, zero_entry = -1;
    long str_off = 0, str_sz = 0;
    uint64_t val;
    long free_at = -1;
    long str_val = -1;
    long need = (long)strlen(libname) + 1;
    long str_pad_run = 0, str_pad_start = -1, q;
    long dyn_pad;
    uint64_t phoff, shoff;
    uint16_t phes, phn, shes, shn, i;

    if (!elf_find(data, size, libname, &dyn)) return -1;   /* не ELF64 */
    phoff = rd64(data + 32);
    phes = rd16(data + 54); phn = rd16(data + 56);
    for (i = 0; i < phn; ++i) {
        long ph = (long)(phoff + (uint64_t)i * phes);
        if (rd32(data + ph) == 2) { dyn = (long)rd64(data + ph + 8); dynsz = (long)rd64(data + ph + 32); break; }
    }
    if (dynsz <= 0) { fprintf(stderr, "inject ELF: no PT_DYNAMIC\n"); return -1; }

    for (p = dyn; p + 16 <= dyn + dynsz; p += 16) {
        uint64_t tag = rd64(data + p);
        if (tag == 0) { zero_entry = p; break; }
        last_entry = p;
    }
    if (zero_entry < 0) { fprintf(stderr, "inject ELF: no DT_NULL\n"); return -1; }

    if (elf64_find_sec(data, size, ".dynstr", &str_off, &str_sz) != 0) {
        fprintf(stderr, "inject ELF: cannot find .dynstr\n"); return -1;
    }

    /* дубликат? */
    for (p = dyn; p <= zero_entry; p += 16) {
        val = rd64(data + p + 8);
        if (rd64(data + p) == 1 && (long)val < str_sz &&
            strcmp((const char*)data + str_off + val, libname) == 0) {
            printf("inject: DT_NEEDED '%s' already present\n", libname);
            return 2;
        }
    }

    /* строка уже есть в .dynstr? */
    for (q = str_off; q + need < str_off + str_sz; ++q) {
        if (memcmp(data + q, libname, (size_t)need) == 0 && (q == str_off || data[q-1] == 0)) {
            str_val = q - str_off; break;
        }
    }

    /* нулевой pad ВНУТРИ sh_size(.dynstr) */
    for (q = str_off + str_sz; q > str_off; ) {
        --q;
        if (data[q] == 0) { ++str_pad_run; if (str_pad_start < 0) str_pad_start = q; }
        else break;
    }
    if (str_val < 0 && str_pad_run >= need) {
        memcpy(data + str_pad_start, libname, (size_t)(need - 1));
        data[str_pad_start + need - 1] = 0;
        str_val = str_pad_start - str_off;
    }

    dyn_pad = zero_entry - (last_entry + 16);

    if (str_val >= 0) {
        /* --- режим A: in-place --- */
        if (dyn_pad >= 16) {
            free_at = last_entry + 16;
        } else if (zero_entry + 16 <= dyn + dynsz) {
            memmove(data + zero_entry + 16, data + zero_entry, (size_t)((dyn + dynsz) - zero_entry));
            free_at = zero_entry;
        } else {
            fprintf(stderr, "inject ELF: no room in .dynamic\n"); return -1;
        }
        w64(data + free_at, 1);
        w64(data + free_at + 8, (uint64_t)str_val);
        printf("inject ELF: added DT_NEEDED '%s' (stroff=%ld slot=0x%lx, in-place)%s\n",
               libname, str_val, (unsigned long)free_at, dry ? " [dry-run]" : "");
        if (dry) return 0;
        {
            FILE* fw = fopen(path, "r+b");
            if (!fw) { perror(path); return 1; }
            if (fwrite(data, 1, (size_t)size, fw) != (size_t)size) { perror("write"); fclose(fw); return 1; }
            fclose(fw);
        }
        return 0;
    }

    /* --- режим B: новый PT_LOAD в конце файла (строка + мини-.dynamic) --- */
    {
        long new_dynsz = 32;                            /* DT_NEEDED + DT_NULL */
        long align = 0x1000;
        long seg_off = (size + align - 1) / align * align;
        long str_new_off, dyn_new_off;
        long seg_filesz = need + new_dynsz;
        uint64_t last_vaddr = 0, last_poff = 0, last_psz = 0, last_memsz = 0;
        long new_vaddr;
        int have_ph_free = 0;
        long hdr_end;
        long delta;

        for (i = 0; i < phn; ++i) {
            long ph = (long)(phoff + (uint64_t)i * phes);
            if (rd32(data + ph) == 1) {
                last_poff  = rd64(data + ph + 8);
                last_vaddr = rd64(data + ph + 16);
                last_psz   = rd64(data + ph + 32);
                last_memsz = rd64(data + ph + 40);
            }
        }
        if (last_psz == 0) { fprintf(stderr, "inject ELF: no PT_LOAD found\n"); return -1; }
        new_vaddr = (long)last_vaddr + (long)last_memsz;
        new_vaddr = (new_vaddr + (align - 1)) & ~(long)(align - 1);

        hdr_end = (long)(phoff + (uint64_t)phn * phes);
        if (hdr_end + phes <= (long)last_poff + (long)last_psz) {
            int allzero = 1;
            for (q = hdr_end; q < hdr_end + phes; ++q) if (data[q]) { allzero = 0; break; }
            if (allzero) have_ph_free = 1;
        }

        if (have_ph_free) {
            delta = seg_off - size;
        } else {
            delta = (long)phes + seg_off - size;
            seg_off += phes;
        }
        str_new_off = seg_off;
        dyn_new_off = seg_off + need;

        if (dry) {
            printf("inject ELF: would add DT_NEEDED '%s' via new PT_LOAD (%s), file grows by %ld bytes\n",
                   libname, have_ph_free ? "phnum reserve" : "phdr table grow",
                   seg_off + seg_filesz - size);
            return 0;
        }

        {
            long newsize = seg_off + seg_filesz;
            unsigned char* nd = realloc(data, (size_t)newsize);
            long ph;
            long old_end = have_ph_free ? seg_off : (seg_off - phes);
            if (!nd) { fprintf(stderr, "inject ELF: OOM\n"); return 1; }
            data = nd; *pdata = nd;
            memset(data + size, 0, (size_t)(newsize - size));

            if (!have_ph_free) {
                memmove(data + hdr_end + phes, data + hdr_end, (size_t)(old_end - hdr_end));
                memset(data + hdr_end, 0, (size_t)phes);
            }

            memcpy(data + str_new_off, libname, (size_t)(need - 1));
            data[str_new_off + need - 1] = 0;
            w64(data + dyn_new_off, 1);
            w64(data + dyn_new_off + 8, (uint64_t)need);
            w64(data + dyn_new_off + 16, 0);
            w64(data + dyn_new_off + 24, 0);

            /* заполняем первые два свободных слота таблицы сегментов:
               - если был резерв linker'а - пишем с hdr_end;
               - иначе мы сдвинули таблицу на +phes и освободили hdr_end,
                 второй слот - конец сдвинутой таблицы (hdr_end+phes). */
            ph = hdr_end;
            if (!have_ph_free) { /* слоты: [hdr_end] пустой + старые после него; второй новый - после таблицы */ }
            {
                long ph2 = have_ph_free ? (hdr_end + phes) : (hdr_end + (long)phes * 2);
                w32(data + ph + 0, 2);                    /* PT_DYNAMIC */
                w32(data + ph + 4, 6);                    /* RW */
                w64(data + ph + 8,  (uint64_t)dyn_new_off);
                w64(data + ph + 16, (uint64_t)(new_vaddr + need));
                w64(data + ph + 24, (uint64_t)(new_vaddr + need));
                w64(data + ph + 32, (uint64_t)new_dynsz);
                w64(data + ph + 40, (uint64_t)new_dynsz);
                w64(data + ph + 48, 8);
                w32(data + ph2 + 0, 1);                   /* PT_LOAD */
                w32(data + ph2 + 4, 6);                   /* RW */
                w64(data + ph2 + 8,  (uint64_t)seg_off);
                w64(data + ph2 + 16, (uint64_t)new_vaddr);
                w64(data + ph2 + 24, (uint64_t)new_vaddr);
                w64(data + ph2 + 32, (uint64_t)seg_filesz);
                w64(data + ph2 + 40, (uint64_t)seg_filesz);
                w64(data + ph2 + 48, (uint64_t)align);
            }
            w16(data + 56, phn + 2);                      /* e_phnum += 2 */

            /* сдвиг файловых смещений старых областей */
            shoff = rd64(data + 40);
            if ((long)shoff >= old_end) w64(data + 40, (uint64_t)(shoff + delta));
            for (i = 0; i < phn; ++i) {
                long tph = (long)(phoff + (uint64_t)i * phes);
                long o = (long)rd64(data + tph + 8);
                if (o >= old_end) w64(data + tph + 8, (uint64_t)(o + delta));
            }
            shes = rd16(data + 58); shn = rd16(data + 60);
            for (i = 0; i < shn; ++i) {
                long s = (long)(shoff + (long)i * shes);
                long o = (long)rd64(data + s + 24);
                if (o >= old_end) w64(data + s + 24, (uint64_t)(o + delta));
            }
            *psize = newsize;

            {
                FILE* fw = fopen(path, "wb");
                if (!fw) { perror(path); return 1; }
                if (fwrite(data, 1, (size_t)newsize, fw) != (size_t)newsize) { perror("write"); fclose(fw); return 1; }
                fclose(fw);
            }
            printf("inject ELF: added DT_NEEDED '%s' (new PT_LOAD at 0x%lx vaddr 0x%lx, %s)\n",
                   libname, (unsigned long)seg_off, (unsigned long)new_vaddr,
                   have_ph_free ? "phnum reserve" : "phdr table grow");
            return 0;
        }
    }
}

static int cmd_inject(const char* path, const char* libname, int dry) {
    FILE* f = fopen(path, "rb");
    long size;
    unsigned char* data;
    int rc = 1;
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
    if (size <= 0 || (size_t)size > 256u * 1024u * 1024u) { fprintf(stderr, "bad file size\n"); fclose(f); return 1; }
    data = malloc((size_t)size);
    if (!data) { fclose(f); return 1; }
    if (fread(data, 1, (size_t)size, f) != (size_t)size) { perror("read"); free(data); fclose(f); return 1; }
    fclose(f);

    /* ---------------- ELF64: DT_NEEDED ---------------- */
    {
        long dyn = 0;
        if (elf_find(data, size, libname, &dyn)) {
            int erc;
            (void)dyn;
            erc = elf_add_dt_needed(path, &data, &size, libname, dry);
            if (erc == 0 || erc == 2) { rc = erc; goto out; }
            /* ошибка -> падаем дальше на проверку PE */
        }
    }
    /* ---------------- PE32+: импорт DLL ---------------- */
    if (size >= 0x40 && data[0] == 'M' && data[1] == 'Z') {
        uint32_t e_lfanew = rd32(data + 0x3C);
        uint32_t coff_off, opt_off, sec_off, nsec, hdr_size;
        long desc_off, i, new_desc_off, insert_at, name_sec = -1;
        uint32_t imp_rva, imp_size, dir_base;
        if ((long)e_lfanew + 24 > size || memcmp(data + e_lfanew, "PE\0\0", 4) != 0) {
            fprintf(stderr, "inject PE: bad signature\n"); goto out;
        }
        coff_off = e_lfanew + 4;
        nsec = rd16(data + coff_off + 2);
        hdr_size = rd16(data + coff_off + 16);
        opt_off = coff_off + 20;
        sec_off = opt_off + hdr_size;
        if (rd16(data + opt_off) != 0x20B) { fprintf(stderr, "inject PE: only PE32+ (x64)\n"); goto out; }
        dir_base = opt_off + 112 + 8;         /* DataDirectory[1] = Import */
        imp_rva  = rd32(data + dir_base);
        imp_size = rd32(data + dir_base + 4);
        if (!imp_rva || !imp_size) { fprintf(stderr, "inject PE: no import dir\n"); goto out; }
        desc_off = pe_rva2off(data, sec_off, nsec, imp_rva);
        if (desc_off < 0) { fprintf(stderr, "inject PE: bad import RVA\n"); goto out; }

        /* список дескрипторов */
        for (i = 0; ; ++i) {
            long ent = desc_off + i * 20;
            uint32_t nrva;
            long noff;
            if (ent + 20 > size) { fprintf(stderr, "inject PE: corrupt imports\n"); goto out; }
            nrva = rd32(data + ent + 12);
            if (nrva == 0) break;
            noff = pe_rva2off(data, sec_off, nsec, nrva);
            if (noff >= 0 && ci_cmp((const char*)data + noff, libname) == 0) {
                printf("inject: import '%s' already present\n", libname); rc = 2; goto out;
            }
        }
        new_desc_off = desc_off + i * 20;     /* текущая терминальная нуль-запись */

        /* самое начало области имён сразу после терминальной записи */
        insert_at = new_desc_off + 20;
        /* находим конец существующих имён */
        {
            long max_end = insert_at, j;
            for (j = 0; j < i; ++j) {
                long ent = desc_off + j * 20;
                long noff = pe_rva2off(data, sec_off, nsec, rd32(data + ent + 12));
                if (noff >= 0) {
                    long e = noff;
                    while (e < size && data[e] != 0) ++e;
                    if (e + 1 > max_end) max_end = e + 1;
                }
            }
            insert_at = max_end;
        }
        for (i = 0; i < (long)nsec; ++i) {
            long s = sec_off + i * 40;
            uint32_t va = rd32(data + s + 12), rsz = rd32(data + s + 16);
            long off = pe_rva2off(data, sec_off, nsec, va);
            if (off >= 0 && insert_at >= off && insert_at < off + (long)rsz) { name_sec = s; break; }
        }
        {
            long need = 8 + (long)strlen(libname) + 1;
            uint32_t va, praw, rsz;
            long sec_file_end;
            uint32_t iat_rva, name_rva;
            if (name_sec < 0) { fprintf(stderr, "inject PE: cannot locate names section\n"); goto out; }
            va = rd32(data + name_sec + 12); praw = rd32(data + name_sec + 20); rsz = rd32(data + name_sec + 16);
            sec_file_end = (long)praw + rsz;
            if (insert_at + need > sec_file_end) {
                fprintf(stderr, "inject PE: no room in raw data (%ld needed, %ld free)\n",
                        need, sec_file_end - insert_at);
                goto out;
            }
            memset(data + insert_at, 0, 8);                 /* IAT: один NULL-энтри */
            memcpy(data + insert_at + 8, libname, strlen(libname) + 1);
            iat_rva  = va + (uint32_t)(insert_at - (long)praw);
            name_rva = iat_rva + 8;
            /* новый дескриптор поверх терминальной нуль-записи */
            w32(data + new_desc_off + 0,  iat_rva);   /* OriginalFirstThunk */
            w32(data + new_desc_off + 4,  0);
            w32(data + new_desc_off + 8,  0);
            w32(data + new_desc_off + 12, name_rva);
            w32(data + new_desc_off + 16, iat_rva);   /* FirstThunk */
            /* новая терминальная нуль-запись сразу после - затирает первые байты
               имени первой DLL... это недопустимо. Проверяем: имена шли ПОСЛЕ
               старой терминальной записи, т.е. insert_at был >= new_desc_off+20.
               Новая терминальная запись должна влезть ДО insert_at. */
            if (new_desc_off + 40 > insert_at) {
                fprintf(stderr, "inject PE: no gap for terminating descriptor\n");
                goto out;
            }
            memset(data + new_desc_off + 20, 0, 20);
            w32(data + dir_base + 4, imp_size + 20);
            printf("inject PE: added import '%s' (iat_rva=0x%x name_rva=0x%x)%s\n",
                   libname, iat_rva, name_rva, dry ? " [dry-run]" : "");
            if (dry) { rc = 0; goto out; }
            f = fopen(path, "r+b");
            if (!f) { perror(path); goto out; }
            if (fwrite(data, 1, (size_t)size, f) != (size_t)size) { perror("write"); fclose(f); goto out; }
            fclose(f);
            printf("injected OK: %s -> %s\n", path, libname);
            rc = 0;
        }
        goto out;
    }

    fprintf(stderr, "inject: unknown file format (not ELF64/PE32+)\n");
out:
    free(data);
    return rc;
}

static void usage(void) {
    fprintf(stderr,
        "usage:\n"
        "  prepatcher hash    <file>\n"
        "  prepatcher patch   <file> <old-hex> <new-hex> [--dry]\n"
        "  prepatcher verify  <file> <hex>\n"
        "  prepatcher inject  <game-binary> [libname] [--dry]\n"
        "      ELF64: adds DT_NEEDED (default libudplib.so)\n"
        "      PE32+: adds import table entry (default udplib.dll)\n");
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
    if (strcmp(argv[1], "inject") == 0) {
        const char* lib = (argc > 3 && argv[3][0] != '-') ? argv[3] : NULL;
        int dry = 0;
        for (int i = 3; i < argc; ++i) if (strcmp(argv[i], "--dry") == 0) dry = 1;
        if (!lib) {
#ifdef _WIN32
            lib = "udplib.dll";
#else
            lib = "libudplib.so";
#endif
        }
        return cmd_inject(argv[2], lib, dry);
    }
    usage();
    return 2;
}
