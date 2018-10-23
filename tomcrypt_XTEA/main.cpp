#include <iostream>
#include <string.h>

struct symmetric_key_xtea {
    unsigned long A[32], B[32];
}xte_key;

#define STORE32H(x, y)                          \
do { unsigned __t = __builtin_bswap32 ((x));    \
      memcpy ((y), &__t, 4); } while(0)

#define LOAD32H(x, y)                          \
do { memcpy (&(x), (y), 4);                    \
      (x) = __builtin_bswap32 ((x));} while(0)



int xtea_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key_xtea *skey) {
    unsigned x, sum, K[4];
    /* check arguments */
    if (keylen != 16)    return -1;

    if (num_rounds != 0 && num_rounds != 32) return -2;

    /* load key */
    LOAD32H(K[0], key+0);
    LOAD32H(K[1], key+4);
    LOAD32H(K[2], key+8);
    LOAD32H(K[3], key+12);

    for (x = sum = 0; x < 32; x++) {
        skey->A[x] = (sum + K[sum&3]);
        sum = (sum + 0x9E3779B9UL);
        skey->B[x] = (sum + K[(sum>>11)&3]);
    }
    return 0;
}

int xtea_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key_xtea *skey) {
    unsigned y, z;
    int r;

    LOAD32H(y, &pt[0]);
    LOAD32H(z, &pt[4]);
    for (r = 0; r < 32; r += 4) {
        y = (y + ((((z<<4)^(z>>5)) + z) ^ skey->A[r]));
        z = (z + ((((y<<4)^(y>>5)) + y) ^ skey->B[r]));

        y = (y + ((((z<<4)^(z>>5)) + z) ^ skey->A[r+1]));
        z = (z + ((((y<<4)^(y>>5)) + y) ^ skey->B[r+1]));

        y = (y + ((((z<<4)^(z>>5)) + z) ^ skey->A[r+2]));
        z = (z + ((((y<<4)^(y>>5)) + y) ^ skey->B[r+2]));

        y = (y + ((((z<<4)^(z>>5)) + z) ^ skey->A[r+3]));
        z = (z + ((((y<<4)^(y>>5)) + y) ^ skey->B[r+3]));
    }
    STORE32H(y, &ct[0]);
    STORE32H(z, &ct[4]);
    return 0;
}

int xtea_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key_xtea *skey) {
    unsigned y, z;
    int r;

    LOAD32H(y, &ct[0]);
    LOAD32H(z, &ct[4]);
    for (r = 31; r >= 0; r -= 4) {
        z = (z - ((((y<<4)^(y>>5)) + y) ^ skey->B[r]));
        y = (y - ((((z<<4)^(z>>5)) + z) ^ skey->A[r]));

        z = (z - ((((y<<4)^(y>>5)) + y) ^ skey->B[r-1]));
        y = (y - ((((z<<4)^(z>>5)) + z) ^ skey->A[r-1]));

        z = (z - ((((y<<4)^(y>>5)) + y) ^ skey->B[r-2]));
        y = (y - ((((z<<4)^(z>>5)) + z) ^ skey->A[r-2]));

        z = (z - ((((y<<4)^(y>>5)) + y) ^ skey->B[r-3]));
        y = (y - ((((z<<4)^(z>>5)) + z) ^ skey->A[r-3]));
    }
    STORE32H(y, &pt[0]);
    STORE32H(z, &pt[4]);
    return 0;
}

void xtea_done(symmetric_key_xtea *skey) {
    (void)(skey);
}


int main() {
    int block_size = 8;
    unsigned char ct[block_size];
    unsigned char pt[block_size]= {0x28, 0x85, 0x84, 0x2e, 0xa3, 0xe6, 0x99, 0x9b};//v0[i] = 0x2885842e;v1[i] = 0xa3e6999b;
    symmetric_key_xtea skey;
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    int err;

    if((err = xtea_setup(key, 16, 0, &skey)) == 0)
        printf("key sucess\n");
    else
        printf("Setup Error");

    printf("XTEA\ninput\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n");

    xtea_encrypt(pt,ct,&skey);

    printf("Crypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",ct[i]);
    }
    printf("\n");

    xtea_decrypt(ct, pt,&skey);

    printf("Decrypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n\n\n");
    xtea_done(&skey);
    return 0;
}