#ifndef LIBCRYPTO_H
#define LIBCRYPTO_H

#include "stdio.h"
#include "string.h"
#include "stdint.h"
#include "stdlib.h"

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

typedef struct symmetric_key_rc5 {
    uint8_t rounds;
    uint32_t *s;
}rc5_key;

typedef struct symmetric_key_skipjack {
   unsigned char key[10];
}skipjack_key;

typedef struct symmetric_key_safer {
    safer_key_t key;
}safer_key;


#define ROL16(x, y) ((((x)<<(y)) | ((x)>>(16-(y)))) & 0xFFFF)

#define Ac (((uint32_t*)pt)[0])
#define Bc (((uint32_t*)pt)[1])
#define Ad (((uint32_t*)ct)[0])
#define Bd (((uint32_t*)ct)[1])

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

#define byte(x, n) (((x) >> (8 * (n))) & 255)
#define F(x) ((skey->s[0][byte(x,3)] + skey->s[1][byte(x,2)]) ^ skey->s[2][byte(x,1)]) + skey->s[3][byte(x,0)]



	uint16_t tea_decrypt( uint8_t v0, uint8_t v1);
  uint16_t tea_encrypt( uint8_t v0, uint8_t v1);

	void xxtea_encrypt(uint8_t *data, uint8_t data_len);
  void xxtea_decrypt(uint8_t *data, uint8_t data_len);

	void rc4_encrypt(uint8_t *data, uint8_t data_len);
	void rc4_decrypt(uint8_t *data, uint8_t data_len);

  void xtea_encrypt(const void *pt, void *ct, uint32_t *skey);
  void xtea_decrypt(const void *ct, void *pt, uint32_t *skey);

	int rc5_setup(void *key, uint16_t keysize_b, uint8_t rounds, rc5_key *ctx);                        // ok saida igual clion
	void rc5_encrypt(void *pt, void *ct, const rc5_key *ctx);
	void rc5_decrypt(void *ct,void *pt, const rc5_key *ctx);
	void rc5_done(rc5_key *ctx);

    static unsigned g_func(unsigned w, int *kp, unsigned char *key);
    static unsigned ig_func(unsigned w, int *kp, unsigned char *key);
	int skipjack_setup(const unsigned char *key, int keylen, int num_rounds, skipjack_key *skey);      // ok saida igual clion
	int skipjack_encrypt(const unsigned char *pt, unsigned char *ct, skipjack_key *skey);
	int skipjack_decrypt(const unsigned char *ct, unsigned char *pt, skipjack_key *skey);
	void skipjack_done(skipjack_key *skey);

	static void Safer_Expand_Userkey(const unsigned char *userkey_1, const unsigned char *userkey_2, unsigned int nof_rounds, int strengthened, safer_key_t key);
	int safer_setup(const unsigned char *key, int keylen, int numrounds, safer_key *skey);             //ok saida diferente clion
	int safer_encrypt(const unsigned char *block_in, unsigned char *block_out, safer_key *skey);
	int safer_decrypt(const unsigned char *block_in, unsigned char *block_out, safer_key *skey);
    void safer_done(safer_key *skey);


    int rc2_setup_ex(const unsigned char *key, int keylen, int bits, int num_rounds, rc2_key *skey);
	int rc2_setup(const unsigned char *key, int keylen, int num_rounds, rc2_key *skey);				 // ok saida igual clion
	int rc2_encrypt( const unsigned char *pt, unsigned char *ct, const rc2_key *skey);
	int rc2_decrypt( const unsigned char *ct, unsigned char *pt, const rc2_key *skey);
	void rc2_done(rc2_key *skey);

	uint16_t lsb( uint16_t data);
	uint16_t msb( uint16_t data);

#endif