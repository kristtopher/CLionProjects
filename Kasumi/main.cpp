#include <iostream>
#include <string.h>
//#include "tomcrypt.h"

typedef unsigned long long ulong64;
typedef unsigned ulong32;
typedef unsigned u16;
typedef unsigned char safer_key_t[36];
typedef unsigned char safer_block_t[8];

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

typedef struct symmetric_key {
    unsigned char key[10];
}skipjack_key;

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

#define RULE_B 						  \
   tmp  = g_func(w1, &kp, skey->key); \
   tmp1 = w4; w4  = w3;               \
   w3   = w1 ^ w2 ^ x;                \
   w1   = tmp1; w2 = tmp;

#define RULE_A1 					  \
   tmp = w1 ^ w2 ^ x;                 \
   w1  = ig_func(w2, &kp, skey->key); \
   w2  = w3; w3 = w4; w4 = tmp;

#define RULE_B1  					  \
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




static u16 FI( u16 in, u16 subkey ) {
   u16 nine, seven;
   static const u16 S7[128] = {
      54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18,123, 33,
      55,113, 39,114, 21, 67, 65, 12, 47, 73, 46, 27, 25,111,124, 81,
      53, 9,121, 79, 52, 60, 58, 48,101,127, 40,120,104, 70, 71, 43,
      20,122, 72, 61, 23,109, 13,100, 77, 1, 16, 7, 82, 10,105, 98,
      117,116, 76, 11, 89,106, 0,125,118, 99, 86, 69, 30, 57,126, 87,
      112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35,103, 32, 97, 28, 66,
      102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29,115, 44,
      64,107,108, 24,110, 83, 36, 78, 42, 19, 15, 41, 88,119, 59, 3 };
  static const u16 S9[512] = {
      167,239,161,379,391,334, 9,338, 38,226, 48,358,452,385, 90,397,
      183,253,147,331,415,340, 51,362,306,500,262, 82,216,159,356,177,
      175,241,489, 37,206, 17, 0,333, 44,254,378, 58,143,220, 81,400,
       95, 3,315,245, 54,235,218,405,472,264,172,494,371,290,399, 76,
      165,197,395,121,257,480,423,212,240, 28,462,176,406,507,288,223,
      501,407,249,265, 89,186,221,428,164, 74,440,196,458,421,350,163,
      232,158,134,354, 13,250,491,142,191, 69,193,425,152,227,366,135,
      344,300,276,242,437,320,113,278, 11,243, 87,317, 36, 93,496, 27,
      487,446,482, 41, 68,156,457,131,326,403,339, 20, 39,115,442,124,
      475,384,508, 53,112,170,479,151,126,169, 73,268,279,321,168,364,
      363,292, 46,499,393,327,324, 24,456,267,157,460,488,426,309,229,
      439,506,208,271,349,401,434,236, 16,209,359, 52, 56,120,199,277,
      465,416,252,287,246, 6, 83,305,420,345,153,502, 65, 61,244,282,
      173,222,418, 67,386,368,261,101,476,291,195,430, 49, 79,166,330,
      280,383,373,128,382,408,155,495,367,388,274,107,459,417, 62,454,
      132,225,203,316,234, 14,301, 91,503,286,424,211,347,307,140,374,
       35,103,125,427, 19,214,453,146,498,314,444,230,256,329,198,285,
       50,116, 78,410, 10,205,510,171,231, 45,139,467, 29, 86,505, 32,
       72, 26,342,150,313,490,431,238,411,325,149,473, 40,119,174,355,
      185,233,389, 71,448,273,372, 55,110,178,322, 12,469,392,369,190,
        1,109,375,137,181, 88, 75,308,260,484, 98,272,370,275,412,111,
      336,318, 4,504,492,259,304, 77,337,435, 21,357,303,332,483, 18,
       47, 85, 25,497,474,289,100,269,296,478,270,106, 31,104,433, 84,
      414,486,394, 96, 99,154,511,148,413,361,409,255,162,215,302,201,
      266,351,343,144,441,365,108,298,251, 34,182,509,138,210,335,133,
      311,352,328,141,396,346,123,319,450,281,429,228,443,481, 92,404,
      485,422,248,297, 23,213,130,466, 22,217,283, 70,294,360,419,127,
      312,377, 7,468,194, 2,117,295,463,258,224,447,247,187, 80,398,
      284,353,105,390,299,471,470,184, 57,200,348, 63,204,188, 33,451,
       97, 30,310,219, 94,160,129,493, 64,179,263,102,189,207,114,402,
      438,477,387,122,192, 42,381, 5,145,118,180,449,293,323,136,380,
       43, 66, 60,455,341,445,202,432, 8,237, 15,376,436,464, 59,461};

  /* The sixteen bit input is split into two unequal halves, *
   * nine bits and seven bits - as is the subkey            */

  nine  = (u16)(in>>7)&0x1FF;
  seven = (u16)(in&0x7F);

  /* Now run the various operations */
  nine   = (u16)(S9[nine] ^ seven);
  seven  = (u16)(S7[seven] ^ (nine & 0x7F));
  seven ^= (subkey>>9);
  nine  ^= (subkey&0x1FF);
  nine   = (u16)(S9[nine] ^ seven);
  seven  = (u16)(S7[seven] ^ (nine & 0x7F));
  return (u16)(seven<<9) + nine;
}

static ulong32 FO( ulong32 in, int round_no, symmetric_key_kasumi *key)
{
   u16 left, right;

  /* Split the input into two 16-bit words */
  left = (u16)(in>>16);
  right = (u16) in&0xFFFF;

  /* Now apply the same basic transformation three times */
  left ^= key->KOi1[round_no];
  left = FI( left, key->KIi1[round_no] );
  left ^= right;

  right ^= key->KOi2[round_no];
  right = FI( right, key->KIi2[round_no] );
  right ^= left;

  left ^= key->KOi3[round_no];
  left = FI( left, key->KIi3[round_no] );
  left ^= right;

  return (((ulong32)right)<<16)+left;
}

static ulong32 FL( ulong32 in, int round_no, symmetric_key_kasumi *key )
{
    u16 l, r, a, b;
    /* split out the left and right halves */
    l = (u16)(in>>16);
    r = (u16)(in)&0xFFFF;
    /* do the FL() operations           */
    a = (u16) (l & key->KLi1[round_no]);
    r ^= ROL16(a,1);
    b = (u16)(r | key->KLi2[round_no]);
    l ^= ROL16(b,1);
    /* put the two halves back together */

    return (((ulong32)l)<<16) + r;
}

int kasumi_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key_kasumi *skey)
{
    ulong32 left, right, temp;
    int n;

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);

    LOAD32H(left, pt);
    LOAD32H(right, pt+4);

    for (n = 0; n <= 7; ) {
        temp = FL(left,  n,   skey);
        temp = FO(temp,  n++, skey);
        right ^= temp;
        temp = FO(right, n,   skey);
        temp = FL(temp,  n++, skey);
        left ^= temp;
    }

    STORE32H(left, ct);
    STORE32H(right, ct+4);

    return CRYPT_OK;
}

int kasumi_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key_kasumi *skey) {
    ulong32 left, right, temp;
    int n;

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);

    LOAD32H(left, ct);
    LOAD32H(right, ct+4);

    for (n = 7; n >= 0; ) {
        temp = FO(right, n,   skey);
        temp = FL(temp,  n--, skey);
        left ^= temp;
        temp = FL(left,  n,   skey);
        temp = FO(temp,  n--, skey);
        right ^= temp;
    }

    STORE32H(left, pt);
    STORE32H(right, pt+4);

    return CRYPT_OK;
}

int kasumi_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key_kasumi *skey) {
    static const u16 C[8] = { 0x0123,0x4567,0x89AB,0xCDEF, 0xFEDC,0xBA98,0x7654,0x3210 };
    u16 ukey[8], Kprime[8];
    int n;

    LTC_ARGCHK(key  != NULL);
    LTC_ARGCHK(skey != NULL);

    if (keylen != 16)
       return CRYPT_INVALID_KEYSIZE;

    if (num_rounds != 0 && num_rounds != 8)
       return CRYPT_INVALID_ROUNDS;

    /* Start by ensuring the subkeys are endian correct on a 16-bit basis */
    for (n = 0; n < 8; n++ )
        ukey[n] = (((u16)key[2*n]) << 8) | key[2*n+1];

    /* Now build the K'[] keys */
    for (n = 0; n < 8; n++)
        Kprime[n] = ukey[n] ^ C[n];

    /* Finally construct the various sub keys */
    for(n = 0; n < 8; n++) {
        skey->KLi1[n] = ROL16(ukey[n],1);
        skey->KLi2[n] = Kprime[(n+2)&0x7];
        skey->KOi1[n] = ROL16(ukey[(n+1)&0x7],5);
        skey->KOi2[n] = ROL16(ukey[(n+5)&0x7],8);
        skey->KOi3[n] = ROL16(ukey[(n+6)&0x7],13);
        skey->KIi1[n] = Kprime[(n+4)&0x7];
        skey->KIi2[n] = Kprime[(n+3)&0x7];
        skey->KIi3[n] = Kprime[(n+7)&0x7];
    }
    return CRYPT_OK;
}

void kasumi_done(symmetric_key_kasumi *skey) {
    (void)(skey);
}


int main() {
    int block_size = 8;
    unsigned char ct[block_size];
    unsigned char pt[block_size]= {0x28, 0x85, 0x84, 0x2e, 0xa3, 0xe6, 0x99, 0x9b};//v0[i] = 0x2885842e;v1[i] = 0xa3e6999b;
    symmetric_key_kasumi skey;
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    int err;

    if((err = kasumi_setup(key, 16, 0, &skey)) == CRYPT_OK)
        printf("key sucess\n");
    else
        printf("Setup Error\n");

    printf("Kasumi\ninput\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n");

    kasumi_encrypt(pt,ct,&skey);

    printf("Crypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",ct[i]);
    }
    printf("\n");

    kasumi_decrypt(ct, pt,&skey);

    printf("Decrypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n\n\n");
    kasumi_done(&skey);
    return 0;
}