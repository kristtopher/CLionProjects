#include <iostream>

int count = 0;

typedef unsigned long long ulong64;
typedef unsigned ulong32;
typedef unsigned u16;
typedef unsigned char safer_key_t[36];
typedef unsigned char safer_block_t[8];

typedef struct symmetric_key_rc2 {
    unsigned xkey[64];
}rc2_key;

typedef struct symmetric_key_xtea {
    unsigned AT[4];
}xtea_key;

typedef struct symmetric_key_des {
    ulong32 ek[32], dk[32];
}des_key;

typedef struct rc5_ctx_st {
    uint8_t rounds;
    uint32_t *s;
}rc5_ctx_t;

//typedef struct symmetric_key {
//    unsigned char key[10];
//}skipjack_key;

typedef struct symmetric_key_safer {
    safer_key_t key;
}safer_key;

typedef  struct symmetric_key_kasumi {
    ulong32 KLi1[8], KLi2[8],
            KOi1[8], KOi2[8], KOi3[8],
            KIi1[8], KIi2[8], KIi3[8];
}kasumi_key;


#define ROL16(x, y) ((((x)<<(y)) | ((x)>>(16-(y)))) & 0xFFFF)

#define A (((uint32_t*)buffer)[0])
#define B (((uint32_t*)buffer)[1])

#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))
#define ROTR32(v,n) (((v)>>(n))|((v)<<(32-(n))))


#define CRYPT_OK 0
#define CRYPT_INVALID_KEYSIZE -1
#define CRYPT_INVALID_ROUNDS -2
#define XMEMCPY memcpy
#define STORE32H(x, y)                          \
do { ulong32 __t = __builtin_bswap32 ((x));     \
      XMEMCPY ((y), &__t, 4); } while(0)

#define LOAD32H(x, y)                           \
do { XMEMCPY (&(x), (y), 4);                    \
      (x) = __builtin_bswap32 ((x)); } while(0)
#define RULE_A                        \
   tmp = g_func(w1, &kp, skey->key);  \
   w1  = tmp ^ w4 ^ x;                \
   w4  = w3; w3 = w2;                 \
   w2  = tmp;

#define RULE_B              \
   tmp  = g_func(w1, &kp, skey->key); \
   tmp1 = w4; w4  = w3;               \
   w3   = w1 ^ w2 ^ x;                \
   w1   = tmp1; w2 = tmp;

#define RULE_A1             \
   tmp = w1 ^ w2 ^ x;                 \
   w1  = ig_func(w2, &kp, skey->key); \
   w2  = w3; w3 = w4; w4 = tmp;

#define RULE_B1             \
   tmp = ig_func(w2, &kp, skey->key); \
   w2  = tmp ^ w3 ^ x;                \
   w3  = w4; w4 = w1; w1 = tmp;

#define NORETURN
#define crypt_argchk(v, s, d) NORETURN
#define LTC_ARGCHK(x) do { if (!(x)) { crypt_argchk(#x, __FILE__, __LINE__); } }while(0)

// safer
#define ROL8(x, n)                    \
((unsigned char)((unsigned int)(x) << (n) | (unsigned int)((x) & 0xFF) >> (8 - (n))))

#define EXP(x)       safer_ebox[(x) & 0xFF]
#define LOG(x)       safer_lbox[(x) & 0xFF]
#define PHT(x, y)    { y += x; x += y; }
#define IPHT(x, y)   { x -= y; y -= x; }
#define LTC_SAFER_K64_DEFAULT_NOF_ROUNDS     6
#define LTC_SAFER_MAX_NOF_ROUNDS            13
#define LTC_SAFER_BLOCK_LEN                  8
#define LTC_SAFER_KEY_LEN     (1 + LTC_SAFER_BLOCK_LEN * (1 + 2 * LTC_SAFER_MAX_NOF_ROUNDS))

static const unsigned char permute[256] = {
        217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
        198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
         23,154, 89,245,135,179, 79, 19, 97, 69,109,141,  9,129,125, 50,
        189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
         84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
         18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
        111,191, 14,218, 70,105,  7, 87, 39,242, 29,155,188,148, 67,  3,
        248, 17,199,246,144,239, 62,231,  6,195,213, 47,200,102, 30,215,
          8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
        150, 26,210,113, 90, 21, 73,116, 75,159,208, 94,  4, 24,164,236,
        194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
        153,124, 58,133, 35,184,180,122,252,  2, 54, 91, 37, 85,151, 49,
         45, 93,250,152,227,138,146,174,  5,223, 41, 16,103,108,186,201,
        211,  0,230,207,225,158,168, 44, 99, 22,  1, 63, 88,226,137,169,
         13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
        197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
};


int rc2_setup_ex(const unsigned char *key, int keylen, int bits, int num_rounds, symmetric_key_rc2 *skey)
{
   unsigned *xkey = skey->xkey;
   unsigned char tmp[128];
   unsigned T8, TM;
   int i;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(skey != NULL);

   if (keylen == 0 || keylen > 128 || bits > 1024) {
      return CRYPT_INVALID_KEYSIZE;
   }
   if (bits == 0) {
      bits = 1024;
   }

   if (num_rounds != 0 && num_rounds != 16) {
      return CRYPT_INVALID_ROUNDS;
   }

   for (i = 0; i < keylen; i++) {
      tmp[i] = key[i] & 255;
   }

   /* Phase 1: Expand input key to 128 bytes */
   if (keylen < 128) {
      for (i = keylen; i < 128; i++) {
         tmp[i] = permute[(tmp[i - 1] + tmp[i - keylen]) & 255];
      }
   }

   /* Phase 2 - reduce effective key size to "bits" */
   T8   = (unsigned)(bits+7)>>3;
   TM   = (255 >> (unsigned)(7 & -bits));
   tmp[128 - T8] = permute[tmp[128 - T8] & TM];
   for (i = 127 - T8; i >= 0; i--) {
      tmp[i] = permute[tmp[i + 1] ^ tmp[i + T8]];
   }

   /* Phase 3 - copy to xkey in little-endian order */
   for (i = 0; i < 64; i++) {
      xkey[i] =  (unsigned)tmp[2*i] + ((unsigned)tmp[2*i+1] << 8);
   }

   return CRYPT_OK;
}

int rc2_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key_rc2 *skey) {
   return rc2_setup_ex(key, keylen, keylen * 8, num_rounds, skey);
}

int rc2_encrypt( const unsigned char *pt, unsigned char *ct, const symmetric_key_rc2 *skey){
    const unsigned *xkey;
    unsigned x76, x54, x32, x10, i;

    LTC_ARGCHK(pt  != NULL);
    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(skey   != NULL);

    xkey = skey->xkey;

    x76 = ((unsigned)pt[7] << 8) + (unsigned)pt[6];
    x54 = ((unsigned)pt[5] << 8) + (unsigned)pt[4];
    x32 = ((unsigned)pt[3] << 8) + (unsigned)pt[2];
    x10 = ((unsigned)pt[1] << 8) + (unsigned)pt[0];

    for (i = 0; i < 16; i++) {
        x10 = (x10 + (x32 & ~x76) + (x54 & x76) + xkey[4*i+0]) & 0xFFFF;    //9
        x10 = ((x10 << 1) | (x10 >> 15));                                   //3

        x32 = (x32 + (x54 & ~x10) + (x76 & x10) + xkey[4*i+1]) & 0xFFFF;    //9
        x32 = ((x32 << 2) | (x32 >> 14));                                   //3

        x54 = (x54 + (x76 & ~x32) + (x10 & x32) + xkey[4*i+2]) & 0xFFFF;    //9
        x54 = ((x54 << 3) | (x54 >> 13));                                   //3

        x76 = (x76 + (x10 & ~x54) + (x32 & x54) + xkey[4*i+3]) & 0xFFFF;    //9
        x76 = ((x76 << 5) | (x76 >> 11));                                   //3

        count += 48;
        if (i == 4 || i == 10) {
            x10 = (x10 + xkey[x76 & 63]) & 0xFFFF;
            x32 = (x32 + xkey[x10 & 63]) & 0xFFFF;
            x54 = (x54 + xkey[x32 & 63]) & 0xFFFF;
            x76 = (x76 + xkey[x54 & 63]) & 0xFFFF;
            count += 12;
        }
    }

    ct[0] = (unsigned char)x10;
    ct[1] = (unsigned char)(x10 >> 8);
    ct[2] = (unsigned char)x32;
    ct[3] = (unsigned char)(x32 >> 8);
    ct[4] = (unsigned char)x54;
    ct[5] = (unsigned char)(x54 >> 8);
    ct[6] = (unsigned char)x76;
    ct[7] = (unsigned char)(x76 >> 8);

    return CRYPT_OK;
}


int rc2_decrypt( const unsigned char *ct, unsigned char *pt, const symmetric_key_rc2 *skey){
    unsigned x76, x54, x32, x10;
    const unsigned *xkey;
    int i;

    LTC_ARGCHK(pt  != NULL);
    LTC_ARGCHK(ct != NULL);
    LTC_ARGCHK(skey   != NULL);

    xkey = skey->xkey;

    x76 = ((unsigned)ct[7] << 8) + (unsigned)ct[6];
    x54 = ((unsigned)ct[5] << 8) + (unsigned)ct[4];
    x32 = ((unsigned)ct[3] << 8) + (unsigned)ct[2];
    x10 = ((unsigned)ct[1] << 8) + (unsigned)ct[0];

    for (i = 15; i >= 0; i--) {
        if (i == 4 || i == 10) {
            x76 = (x76 - xkey[x54 & 63]) & 0xFFFF;
            x54 = (x54 - xkey[x32 & 63]) & 0xFFFF;
            x32 = (x32 - xkey[x10 & 63]) & 0xFFFF;
            x10 = (x10 - xkey[x76 & 63]) & 0xFFFF;
        }

        x76 = ((x76 << 11) | (x76 >> 5));
        x76 = (x76 - ((x10 & ~x54) + (x32 & x54) + xkey[4*i+3])) & 0xFFFF;

        x54 = ((x54 << 13) | (x54 >> 3));
        x54 = (x54 - ((x76 & ~x32) + (x10 & x32) + xkey[4*i+2])) & 0xFFFF;

        x32 = ((x32 << 14) | (x32 >> 2));
        x32 = (x32 - ((x54 & ~x10) + (x76 & x10) + xkey[4*i+1])) & 0xFFFF;

        x10 = ((x10 << 15) | (x10 >> 1));
        x10 = (x10 - ((x32 & ~x76) + (x54 & x76) + xkey[4*i+0])) & 0xFFFF;
    }

    pt[0] = (unsigned char)x10;
    pt[1] = (unsigned char)(x10 >> 8);
    pt[2] = (unsigned char)x32;
    pt[3] = (unsigned char)(x32 >> 8);
    pt[4] = (unsigned char)x54;
    pt[5] = (unsigned char)(x54 >> 8);
    pt[6] = (unsigned char)x76;
    pt[7] = (unsigned char)(x76 >> 8);

    return CRYPT_OK;
}

void rc2_done(symmetric_key_rc2 *skey) {
    (void)(skey);
}

int main() {
    int block_size = 8;
    unsigned char ct[block_size];
    unsigned char pt[block_size]= {0x28, 0x85, 0x84, 0x2e, 0xa3, 0xe6, 0x99, 0x9b};//v0[i] = 0x2885842e;v1[i] = 0xa3e6999b;
    symmetric_key_rc2 skey;
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    int err;


    if((err = rc2_setup(key, 16, 0, &skey)) == CRYPT_OK)
        printf("key sucess\n");
    else
        printf("Setup Error\n");
    printf("RC2\ninput\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n");

    rc2_encrypt(pt,ct,&skey);

    printf("Crypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",ct[i]);
    }

    printf("\n>>%d\n",count);

    rc2_decrypt(ct, pt,&skey);

    printf("Decrypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n\n\n");
    rc2_done(&skey);
    return 0;
}