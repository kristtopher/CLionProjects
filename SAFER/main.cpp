#include <iostream>

//#include "tomcrypt.h"

#define NORETURN
#define crypt_argchk(v, s, d) NORETURN
#define LTC_ARGCHK(x) do { if (!(x)) { crypt_argchk(#x, __FILE__, __LINE__); } }while(0)
#define CRYPT_OK 0
#define CRYPT_INVALID_KEYSIZE -1
#define CRYPT_INVALID_ROUNDS -2


#define ROL8(x, n)                          \
((unsigned char)((unsigned int)(x) << (n) | (unsigned int)((x) & 0xFF) >> (8 - (n))))

#define EXP(x)       safer_ebox[(x) & 0xFF]
#define LOG(x)       safer_lbox[(x) & 0xFF]
#define PHT(x, y)    { y += x; x += y; }
#define IPHT(x, y)   { x -= y; y -= x; }
#define LTC_SAFER_K64_DEFAULT_NOF_ROUNDS     6
#define LTC_SAFER_MAX_NOF_ROUNDS            13
#define LTC_SAFER_BLOCK_LEN                  8
#define LTC_SAFER_KEY_LEN     (1 + LTC_SAFER_BLOCK_LEN * (1 + 2 * LTC_SAFER_MAX_NOF_ROUNDS))
typedef unsigned char safer_block_t[LTC_SAFER_BLOCK_LEN];
typedef unsigned char safer_key_t[LTC_SAFER_KEY_LEN];

typedef struct symmetric_key_safer {
    safer_key_t key;
}symmetric_key_safer;


static const unsigned char safer_ebox[256] = {
        1,  45, 226, 147, 190,  69,  21, 174, 120,   3, 135, 164, 184,  56, 207,  63,
        8, 103,   9, 148, 235,  38, 168, 107, 189,  24,  52,  27, 187, 191, 114, 247,
        64,  53,  72, 156,  81,  47,  59,  85, 227, 192, 159, 216, 211, 243, 141, 177,
        255, 167,  62, 220, 134, 119, 215, 166,  17, 251, 244, 186, 146, 145, 100, 131,
        241,  51, 239, 218,  44, 181, 178,  43, 136, 209, 153, 203, 140, 132,  29,  20,
        129, 151, 113, 202,  95, 163, 139,  87,  60, 130, 196,  82,  92,  28, 232, 160,
        4, 180, 133,  74, 246,  19,  84, 182, 223,  12,  26, 142, 222, 224,  57, 252,
        32, 155,  36,  78, 169, 152, 158, 171, 242,  96, 208, 108, 234, 250, 199, 217,
        0, 212,  31, 110,  67, 188, 236,  83, 137, 254, 122,  93,  73, 201,  50, 194,
        249, 154, 248, 109,  22, 219,  89, 150,  68, 233, 205, 230,  70,  66, 143,  10,
        193, 204, 185, 101, 176, 210, 198, 172,  30,  65,  98,  41,  46,  14, 116,  80,
        2,  90, 195,  37, 123, 138,  42,  91, 240,   6,  13,  71, 111, 112, 157, 126,
        16, 206,  18,  39, 213,  76,  79, 214, 121,  48, 104,  54, 117, 125, 228, 237,
        128, 106, 144,  55, 162,  94, 118, 170, 197, 127,  61, 175, 165, 229,  25,  97,
        253,  77, 124, 183,  11, 238, 173,  75,  34, 245, 231, 115,  35,  33, 200,   5,
        225, 102, 221, 179,  88, 105,  99,  86,  15, 161,  49, 149,  23,   7,  58,  40
};

/* This is the inverse of ebox or the base 45 logarithm */
static const unsigned char safer_lbox[256] = {
        128,   0, 176,   9,  96, 239, 185, 253,  16,  18, 159, 228, 105, 186, 173, 248,
        192,  56, 194, 101,  79,   6, 148, 252,  25, 222, 106,  27,  93,  78, 168, 130,
        112, 237, 232, 236, 114, 179,  21, 195, 255, 171, 182,  71,  68,   1, 172,  37,
        201, 250, 142,  65,  26,  33, 203, 211,  13, 110, 254,  38,  88, 218,  50,  15,
        32, 169, 157, 132, 152,   5, 156, 187,  34, 140,  99, 231, 197, 225, 115, 198,
        175,  36,  91, 135, 102,  39, 247,  87, 244, 150, 177, 183,  92, 139, 213,  84,
        121, 223, 170, 246,  62, 163, 241,  17, 202, 245, 209,  23, 123, 147, 131, 188,
        189,  82,  30, 235, 174, 204, 214,  53,   8, 200, 138, 180, 226, 205, 191, 217,
        208,  80,  89,  63,  77,  98,  52,  10,  72, 136, 181,  86,  76,  46, 107, 158,
        210,  61,  60,   3,  19, 251, 151,  81, 117,  74, 145, 113,  35, 190, 118,  42,
        95, 249, 212,  85,  11, 220,  55,  49,  22, 116, 215, 119, 167, 230,   7, 219,
        164,  47,  70, 243,  97,  69, 103, 227,  12, 162,  59,  28, 133,  24,   4,  29,
        41, 160, 143, 178,  90, 216, 166, 126, 238, 141,  83,  75, 161, 154, 193,  14,
        122,  73, 165,  44, 129, 196, 199,  54,  43, 127,  67, 149,  51, 242, 108, 104,
        109, 240,   2,  40, 206, 221, 155, 234,  94, 153, 124,  20, 134, 207, 229,  66,
        184,  64, 120,  45,  58, 233, 100,  31, 146, 144, 125,  57, 111, 224, 137,  48
};

/******************* Types ****************************************************/

static void Safer_Expand_Userkey(const unsigned char *userkey_1, const unsigned char *userkey_2, unsigned int nof_rounds, int strengthened, safer_key_t key) {
    unsigned int i, j, k;
    unsigned char ka[LTC_SAFER_BLOCK_LEN + 1];
    unsigned char kb[LTC_SAFER_BLOCK_LEN + 1];

    if (LTC_SAFER_MAX_NOF_ROUNDS < nof_rounds)
        nof_rounds = LTC_SAFER_MAX_NOF_ROUNDS;
    *key++ = (unsigned char) nof_rounds;
    ka[LTC_SAFER_BLOCK_LEN] = (unsigned char) 0;
    kb[LTC_SAFER_BLOCK_LEN] = (unsigned char) 0;
    k = 0;
    for (j = 0; j < LTC_SAFER_BLOCK_LEN; j++) {
        ka[j] = ROL8(userkey_1[j], 5);
        ka[LTC_SAFER_BLOCK_LEN] ^= ka[j];
        kb[j] = *key++ = userkey_2[j];
        kb[LTC_SAFER_BLOCK_LEN] ^= kb[j];
    }
    for (i = 1; i <= nof_rounds; i++) {
        for (j = 0; j < LTC_SAFER_BLOCK_LEN + 1; j++) {
            ka[j] = ROL8(ka[j], 6);
            kb[j] = ROL8(kb[j], 6);
        }
        if (strengthened) {
            k = 2 * i - 1;
            while (k >= (LTC_SAFER_BLOCK_LEN + 1)) { k -= LTC_SAFER_BLOCK_LEN + 1; }
        }
        for (j = 0; j < LTC_SAFER_BLOCK_LEN; j++) {
            if (strengthened) {
                *key++ = (ka[k]
                          + safer_ebox[(int) safer_ebox[(int) ((18 * i + j + 1) & 0xFF)]]) & 0xFF;
                if (++k == (LTC_SAFER_BLOCK_LEN + 1)) { k = 0; }
            } else {
                *key++ = (ka[j] + safer_ebox[(int) safer_ebox[(int) ((18 * i + j + 1) & 0xFF)]]) & 0xFF;
            }
        }
        if (strengthened) {
            k = 2 * i;
            while (k >= (LTC_SAFER_BLOCK_LEN + 1)) { k -= LTC_SAFER_BLOCK_LEN + 1; }
        }
        for (j = 0; j < LTC_SAFER_BLOCK_LEN; j++) {
            if (strengthened) {
                *key++ = (kb[k]
                          + safer_ebox[(int) safer_ebox[(int) ((18 * i + j + 10) & 0xFF)]]) & 0xFF;
                if (++k == (LTC_SAFER_BLOCK_LEN + 1)) { k = 0; }
            } else {
                *key++ = (kb[j] + safer_ebox[(int) safer_ebox[(int) ((18 * i + j + 10) & 0xFF)]]) & 0xFF;
            }
        }
    }
}

int safer_k64_setup(const unsigned char *key, int keylen, int numrounds, symmetric_key_safer *skey) {
    LTC_ARGCHK(key != NULL);
    LTC_ARGCHK(skey != NULL);
    if (numrounds != 0 && (numrounds < 6 || numrounds > LTC_SAFER_MAX_NOF_ROUNDS))
        return CRYPT_INVALID_ROUNDS;
    if (keylen != 8)
        return CRYPT_INVALID_KEYSIZE;
    Safer_Expand_Userkey(key, key, (unsigned int)(numrounds != 0 ?numrounds:LTC_SAFER_K64_DEFAULT_NOF_ROUNDS), 0, skey->key);
    return CRYPT_OK;
}


int safer_ecb_encrypt(const unsigned char *block_in, unsigned char *block_out, symmetric_key_safer *skey) {
    unsigned char a, b, c, d, e, f, g, h, t;
    unsigned int round;
    unsigned char *key;

    LTC_ARGCHK(block_in != NULL);
    LTC_ARGCHK(block_out != NULL);
    LTC_ARGCHK(skey != NULL);

    key = skey->key;
    a = block_in[0]; b = block_in[1]; c = block_in[2]; d = block_in[3];
    e = block_in[4]; f = block_in[5]; g = block_in[6]; h = block_in[7];
    if (LTC_SAFER_MAX_NOF_ROUNDS < (round = *key)) round = LTC_SAFER_MAX_NOF_ROUNDS;
    while(round-- > 0)
    {
        a ^= *++key; b += *++key; c += *++key; d ^= *++key;
        e ^= *++key; f += *++key; g += *++key; h ^= *++key;
        a = EXP(a) + *++key; b = LOG(b) ^ *++key;
        c = LOG(c) ^ *++key; d = EXP(d) + *++key;
        e = EXP(e) + *++key; f = LOG(f) ^ *++key;
        g = LOG(g) ^ *++key; h = EXP(h) + *++key;
        PHT(a, b); PHT(c, d); PHT(e, f); PHT(g, h);
        PHT(a, c); PHT(e, g); PHT(b, d); PHT(f, h);
        PHT(a, e); PHT(b, f); PHT(c, g); PHT(d, h);
        t = b; b = e; e = c; c = t; t = d; d = f; f = g; g = t;
    }
    a ^= *++key; b += *++key; c += *++key; d ^= *++key;
    e ^= *++key; f += *++key; g += *++key; h ^= *++key;
    block_out[0] = a & 0xFF; block_out[1] = b & 0xFF;
    block_out[2] = c & 0xFF; block_out[3] = d & 0xFF;
    block_out[4] = e & 0xFF; block_out[5] = f & 0xFF;
    block_out[6] = g & 0xFF; block_out[7] = h & 0xFF;
    return CRYPT_OK;
}

int safer_ecb_decrypt(const unsigned char *block_in, unsigned char *block_out, symmetric_key_safer *skey) {
    unsigned char a, b, c, d, e, f, g, h, t;
    unsigned int round;
    unsigned char *key;

    LTC_ARGCHK(block_in != NULL);
    LTC_ARGCHK(block_out != NULL);
    LTC_ARGCHK(skey != NULL);

    key = skey->key;
    a = block_in[0]; b = block_in[1]; c = block_in[2]; d = block_in[3];
    e = block_in[4]; f = block_in[5]; g = block_in[6]; h = block_in[7];
    if (LTC_SAFER_MAX_NOF_ROUNDS < (round = *key)) round = LTC_SAFER_MAX_NOF_ROUNDS;
    key += LTC_SAFER_BLOCK_LEN * (1 + 2 * round);
    h ^= *key; g -= *--key; f -= *--key; e ^= *--key;
    d ^= *--key; c -= *--key; b -= *--key; a ^= *--key;
    while (round--)
    {
        t = e; e = b; b = c; c = t; t = f; f = d; d = g; g = t;
        IPHT(a, e); IPHT(b, f); IPHT(c, g); IPHT(d, h);
        IPHT(a, c); IPHT(e, g); IPHT(b, d); IPHT(f, h);
        IPHT(a, b); IPHT(c, d); IPHT(e, f); IPHT(g, h);
        h -= *--key; g ^= *--key; f ^= *--key; e -= *--key;
        d -= *--key; c ^= *--key; b ^= *--key; a -= *--key;
        h = LOG(h) ^ *--key; g = EXP(g) - *--key;
        f = EXP(f) - *--key; e = LOG(e) ^ *--key;
        d = LOG(d) ^ *--key; c = EXP(c) - *--key;
        b = EXP(b) - *--key; a = LOG(a) ^ *--key;
    }
    block_out[0] = a & 0xFF; block_out[1] = b & 0xFF;
    block_out[2] = c & 0xFF; block_out[3] = d & 0xFF;
    block_out[4] = e & 0xFF; block_out[5] = f & 0xFF;
    block_out[6] = g & 0xFF; block_out[7] = h & 0xFF;
    return CRYPT_OK;
}



/** Terminate the context
   @param skey    The scheduled key
*/
void safer_done(symmetric_key_safer *skey) {
    (void)(skey);
}

int main() {
    int block_size = 8;
    unsigned char ct[block_size];
    unsigned char pt[block_size]= {0x28, 0x85, 0x84, 0x2e, 0xa3, 0xe6, 0x99, 0x9b};//v0[i] = 0x2885842e;v1[i] = 0xa3e6999b;
    symmetric_key_safer skey;
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    int err;

    if((err = safer_k64_setup(Bkey, 8, 0, &skey)) == CRYPT_OK)
        printf("key sucess\n");
    else
        printf("Setup Error \n");
    printf("safer_k64\ninput\n");

    printf("safer_k64\ninput\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n");

    safer_ecb_encrypt(pt,ct,&skey);

    printf("Crypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",ct[i]);
    }
    printf("\n");

    safer_ecb_decrypt(ct, pt,&skey);

    printf("Decrypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n\n\n");
    safer_done(&skey);
    return 0;
}