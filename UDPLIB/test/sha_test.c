#include <stdio.h>
#include <string.h>
#include "../src/sha256.h"
int main(void){
    char hex[65];
    int fails = 0;
    struct { const char* in; const char* want; } v[] = {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"banana", "2301d83ce7c443fd8a96c148df8b2f2799c231d50742959ff806018cf90245b9"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2ca382283b97e53f0d16"}
    };
    for (size_t i=0;i<sizeof(v)/sizeof(v[0]);++i){
        udplib_sha256_hex(v[i].in, hex);
        if (strcmp(hex, v[i].want)!=0){ printf("FAIL %s -> %s\n", v[i].in, hex); fails++; }
        else printf("PASS sha256(\"%s\")\n", strlen(v[i].in)>20?"<long>":v[i].in);
    }
    /* secure_equals */
    udplib_sha256_hex("banana", hex);
    if(!udplib_secure_equals(hex, v[2].want)){ printf("FAIL secure_equals match\n"); fails++; }
    if(udplib_secure_equals(hex, v[1].want)){ printf("FAIL secure_equals mismatch\n"); fails++; }
    return fails;
}
