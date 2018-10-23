#include <iostream>
#include <stdint.h>
#include <stdlib.h> /* malloc() & free() */
#include <string.h> /* memset() & memcpy() */



#define Ac (((uint32_t*)pt)[0])
#define Bc (((uint32_t*)pt)[1])
#define Ad (((uint32_t*)ct)[0])
#define Bd (((uint32_t*)ct)[1])
#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))
#define ROTR32(v,n) (((v)>>(n))|((v)<<(32-(n))))

typedef struct rc5_ctx_st {
    uint8_t rounds;
    uint32_t *s;
}rc5_ctx_t;


void rc5_enc(void *pt, void *ct, const rc5_ctx_t *ctx){
	uint8_t i;
	Ac += ctx->s[0];
	Bc += ctx->s[1];
	for(i=0; i<ctx->rounds; ++i){
		Ac = ROTL32(Ac^Bc, Bc&31) + ctx->s[(i+1)*2+0];
		Bc = ROTL32(Ac^Bc, Ac&31) + ctx->s[(i+1)*2+1];
	}
    (((uint32_t*)ct)[0]) = Ac;
    (((uint32_t*)ct)[1]) = Bc;
}

void rc5_dec(void *ct,void *pt, const rc5_ctx_t *ctx){
	uint8_t i;
	for(i=ctx->rounds; i>0; --i){
		Bd = ROTR32(Bd - ctx->s[i*2+1], Ad&31) ^ Ad;
		Ad = ROTR32(Ad - ctx->s[i*2+0], Bd&31) ^ Bd;
	}
	Bd -= ctx->s[1];
	Ad -= ctx->s[0];
    (((uint32_t*)pt)[0]) = Ad;
    (((uint32_t*)pt)[1]) = Bd;
}
/*
P32 = 10110111111000010101000101100011 = b7e15163
Q32 = 10011110001101110111100110111001 = 9e3779b9
*/

int rc5_init(void *key, uint16_t keysize_b, uint8_t rounds, rc5_ctx_t *ctx){
	uint16_t c,n,m,j,i,t;
	uint32_t a,b,l[(keysize_b+31)/32];
    uint32_t P32 = 0xb7e15163, Q32 = 0x9e3779b9;
	ctx->rounds = rounds;
	t=2*(rounds+1);
	c=(keysize_b+31)/32;
	ctx->s = (uint32_t*) malloc(t*sizeof(uint32_t));

	memset(l, 0, sizeof(uint32_t)*c);
	memcpy(l, key, (keysize_b+7)/8);

	ctx->s[0] = P32;
	for(i=1; i<t; ++i){
		ctx->s[i] = ctx->s[i-1] + Q32;
	}

	m = ((t>c)?t:c)*3;
	i=j=0;
	a=b=0;
	for(n=0; n<m; ++n){
		a=ctx->s[i]=ROTL32(ctx->s[i]+a+b, 3);
		b=l[j]=ROTL32(l[j]+a+b, (a+b)&31);
		i=(i+1)%t;
		j=(j+1)%c;
	}
    return 0;
}

void rc5_done(rc5_ctx_t *ctx){
	if(ctx->s)
		free(ctx->s);
}


int main() {
    int block_size = 8;
    unsigned char ct[block_size];
    unsigned char pt[block_size]= {0x28, 0x85, 0x84, 0x2e, 0xa3, 0xe6, 0x99, 0x9b};//v0[i] = 0x2885842e;v1[i] = 0xa3e6999b;
    rc5_ctx_t skey;
    unsigned char key[16]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23,0x91,0x42,0xf3,0xc3,0x12,0x1a};
    unsigned char Skey[10] = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D,0x53,0x23};
    unsigned char Bkey[8]  = {0x94,0x74,0xB8,0xE8,0xC7,0x3B,0xCA,0x7D};
    int err;

    if((err = rc5_init(key, 16, 0, &skey)) == 0)
        printf("key sucess\n");
    else
        printf("Setup Error '%s'\n");

    printf("RC5\ninput\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n");

    rc5_enc(pt,ct,&skey);

    printf("Crypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",ct[i]);
    }
    printf("\n");

    rc5_dec(ct, pt,&skey);

    printf("Decrypt\n");
    for (int i = 0; i < block_size; ++i) {
        printf("%x ",pt[i]);
    }
    printf("\n\n\n");
    rc5_done(&skey);
    return 0;
}