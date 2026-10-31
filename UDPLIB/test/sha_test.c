#include <stdio.h>
#include <string.h>
#include "../src/sha256.h"

static int check(const char* in, const char* want) {
    char hex[65];
    udplib_sha256_hex(in, hex);
    if (strcmp(hex, want) != 0) { printf("FAIL \"%s\" -> %s\n", in, hex); return 1; }
    printf("PASS sha256(\"%s\")\n", strlen(in) > 20 ? "<long>" : in);
    return 0;
}

int main(void) {
    int fails = 0;
    fails += check("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    fails += check("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    fails += check("banana", "b493d48364afe44d11c0165cf470a4164d1e2609911ef998be868d46ade3de4e");
    fails += check("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* потоковый test: 1 млн раз 'a' по 1 байту */
    {
        udplib_sha256_ctx ctx; uint8_t d[32]; char hex[65]; int i;
        static const char want[] = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        udplib_sha256_init(&ctx);
        for (i = 0; i < 1000000; ++i) udplib_sha256_update(&ctx, "a", 1);
        udplib_sha256_final(&ctx, d);
        for (i = 0; i < 32; ++i) { sprintf(hex + i*2, "%02x", d[i]); }
        if (strcmp(hex, want) != 0) { printf("FAIL streaming 1M'a'\n"); fails++; }
        else printf("PASS streaming sha256('a' x 1000000)\n");
    }

    /* secure_equals */
    {
        char hex[65];
        udplib_sha256_hex("banana", hex);
        if (!udplib_secure_equals(hex, "b493d48364afe44d11c0165cf470a4164d1e2609911ef998be868d46ade3de4e")) {
            printf("FAIL secure_equals match\n"); fails++;
        }
        if (udplib_secure_equals(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) {
            printf("FAIL secure_equals mismatch\n"); fails++;
        }
        if (udplib_secure_equals("short", "shorter")) { printf("FAIL secure_equals len\n"); fails++; }
        if (!udplib_secure_equals("", "")) { printf("FAIL secure_equals empty\n"); fails++; }
    }
    printf(fails ? "SHA TESTS: %d FAILURES\n" : "SHA TESTS: ALL PASS\n", fails);
    return fails;
}
