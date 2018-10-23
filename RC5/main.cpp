#include <iostream>
//typedef  unsigned long int WORD;        // should be 64-bit = 8 bytes
typedef  unsigned int WORD;             // should be 32-bit = 4 bytes
//typedef  unsigned short int WORD;       // should be 16-bit = 2 bytes
#define w   32                          // word size in bits
#define r   12                          // number of rounds
#define b   16                          // number of bytes in key
#define c   4                           // number words in key
                                        // c = max (1,ceil(8*b/w))
#define t   26                          // size of table S = 2*(r+1) words
WORD S[t];

//WORD P = 0xb7e151628aed2a6b, Q = 0x9e3779b97f4a7c15;//Magic constantes for 64b
WORD P = 0xb7e15163, Q = 0x9e3779b9;    // Magic constantes for 32b
//WORD P = 0xb7e1, Q = 0x9e37;          // Magic constantes for 16b

//rotation operators. x must be usigned, to get logical right shift
#define ROTL(x,y) (((x) << (y&(w-1))) | ((x) >> (w-(y&(w-1)))))
#define ROTR(x,y) (((x) >> (y&(w-1))) | ((x) << (w-(y&(w-1)))))

void RC5_ENCRYPT(WORD *pt, WORD *ct){   //input pt /output ct
    WORD  i, A = pt[0]+S[0], B = pt[1]+S[1];
    for (i = 1; i <= r ; i++) {
        A = ROTL(A^B, B) + S[2 * i];
        B = ROTL(B^A, A) + S[2 * i + 1];
    }
    ct[0] = A;
    ct[1] = B;
}

void RC5_DECRYPT(WORD *ct, WORD *pt){   //input ct /output pt
    WORD  i, B = ct[1], A = ct[0];
    for (i = r; i > 0; i--) {
        B = ROTR(B-S[2*i+1],A)^A;
        A = ROTR(A-S[2*i],B)^B;
    }
    pt[1] = B-S[1];
    pt[0] = A-S[0];
}

void RC5_SETUP(unsigned char *K){   // secret input key k [0...b-1]
    WORD u = w/8, A, B, L[c];
    int i, j,k;
    // initialize l, then S, then mix key into S
    for (i = (b - 1), L[c-1] = 0; i != -1; i--)     L[i/u] = (L[i/u] << 8) + K[i];
    for (S[0]=P,i=1; i < t; i++)    S[i] = S[i-1] + Q;
    for (A=B=0, i=j=k=0; k<(3*t); k++, i = (i+1)%t,j=(j+1)%c) {//3*t >3*c
        A = S[i] = ROTL(S[i]+(A+B),3);
        B = L[j] = ROTL(L[j]+(A+B),(A+B));
    }
}

void printWord(WORD A, WORD B){
//    for (WORD k = 0; k < w; k += 8)   printf("%0.2X",(A>>k)&0xFF);
//    for (WORD k = 0; k < w; k += 8)   printf("%0.2X",(B>>k)&0xFF);
    if (w-8 > 0) {
        for (WORD k = w - 8; k > 0; k -= 8) printf("%0.2X", (A >> k) & 0xFF);
        printf("%0.2X", A & 0xFF);
        for (WORD k = w - 8; k > 0; k -= 8) printf("%0.2X", (B >> k) & 0xFF);
        printf("%0.2X", B & 0xFF);
    }
    else
        printf("%0.2X", B);
}

int main(){
    WORD i, j, pt1[2], pt2[2];
    WORD ct[2]={0x2885842e,0xa3e6999b};
    //WORD ct[2]={0xf,0xb4};
    unsigned char key[b] = {0x94, 0x74, 0xB8, 0xE8, 0xC7, 0x3B, 0xCA, 0x7D, 0x53, 0x23, 0x91, 0x42, 0xf3, 0xc3, 0x12, 0x1a};

    if (sizeof(WORD) != 2 && sizeof(WORD) != 4 && sizeof(WORD) != 8) {
        printf("RC5 error, lengh word %d bytes", sizeof(WORD));
        return 0;
    }

    RC5_SETUP(key);

    for(i=1; i < 6; i++){ // initialize pt1 and key pseudorandomly based on previous ct
        pt1[0] = ct[0];
        pt1[1] = ct[1];
//        for (j = 0; j <  b; j++)
//            key[j] = ct[0]%(255-j);
        //setup, encrypt, and decrypt
        RC5_ENCRYPT(pt1, ct);
        RC5_DECRYPT(ct, pt2);

        //print out resuts, checking for decryption failure
        printf("\n%d. key= ",i);
        for (j=0; j<b;j++)
            printf("%02.2X", key[j]);
        printf("\nplaintext\n");
        printWord(pt1[0],pt1[1]);
        printf("\n-> ciphertext\n");
        printWord(ct[0],ct[1]);
        printf("\n");
        if(pt1[0] != pt2[0] || pt1[1] != pt2[1]) {
            printf("Decryption error\n");
            printWord(pt2[0],pt2[1]);
            return 0;
        } else{
            printf("Decription:\n");
            printWord(pt2[0],pt2[1]);
            printf("\n");
        }
    }
    return 0;
}
