// ftp://ftp.d-link.co.za/DWL/dwl650+/wpa_supplicant-0.4.9
// https://opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/crypto/rc4/rc4.c


/*
 * RC4 stream cipher
 * Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdio.h>


/**
 * rc4 - XOR RC4 stream to given data with skip-stream-start
 * @key: RC4 key
 * @keylen: RC4 key length
 * @data: data to be XOR'ed with RC4 stream
 * @data_len: buf length
 *
 * Generate RC4 pseudo random stream for the given key, skip beginning of the
 * stream, and XOR the end result with the data buffer to perform RC4
 * encryption/decryption.
 */

int count = 0;
int countM = 0;

void rc4(__uint8_t *data, size_t data_len) {
    static const __uint8_t keylen = 16;
    static const __uint8_t  key[keylen] = {0x94, 0x74, 0xB8, 0xE8, 0xC7, 0x3B, 0xCA, 0x7D, 0x53, 0x23, 0x91, 0x42, 0xf3, 0xc3, 0x12, 0x1a};

    __uint32_t i, j, k;
    __uint8_t S[256], *pos;
    int kpos;

    /* Setup RC4 state */
    for (i = 0; i < 256; i++)
        S[i] = i;
    j = 0;
    kpos = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[kpos]) & 0xff;  //3
        kpos++;                             //1
        if (kpos >= keylen)
            kpos = 0;
        i^=j;
        j^=i;
        i^=j;
        countM += 7;
    }

    /* Apply RC4 to data */
    pos = data;
    for (k = 0; k < data_len; k++) {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        i^=j;
        j^=i;
        i^=j;
        *pos++ ^= S[(S[i] + S[j]) & 0xff];
        count += 11;
    }
}


/**
 * rc4 - XOR RC4 stream to given data
 * @buf: data to be XOR'ed with RC4 stream
 * @len: buf length
 * @key: RC4 key
 * @key_len: RC4 key length
 *
 * Generate RC4 pseudo random stream for the given key and XOR this with the
 * data buffer to perform RC4 encryption/decryption.
 */


void printRC4(__uint8_t *buf, size_t len){
    for (int i = 0; i < len; ++i)
        printf("%x ",buf[i]);
    printf("\n");
}

int main() {
    __uint8_t input [] = {0xff, 0x1,0x2, 0x3,0x4,0x5,0x6,0xfa};

    printf("in ");
    printRC4(input, sizeof(input));
    rc4(input, sizeof(input));

    printf("count %d, countM %d all %d\n",count,countM, (countM+count));

    printf("cr ");
    printRC4(input, sizeof(input));
    rc4(input, sizeof(input));
    printf("dc ");
    printRC4(input, sizeof(input));

    return 0;
}