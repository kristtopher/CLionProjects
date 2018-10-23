#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define N 256   // 2^8
char s2[] = "9474B8E8C73BCA7D53239142f3c3121a";
char *key = s2;
unsigned char S[N];


void swap(unsigned char *a, unsigned char *b) {
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA( unsigned char *S) {
    int len, i,j = 0;
    len = strlen(key);
    for(i = 0; i < N; i++)  S[i] = char(i);
    for(i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;
        swap(&S[i], &S[j]);
    }
    return 0;
}

int PRGA(unsigned char *S, char *plaintext, char *ciphertext) {
    int i = 0,j = 0, rnd;

    for(size_t n = 0, len = strlen(plaintext); n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;
        swap(&S[i], &S[j]);
        rnd = S[(S[i] + S[j]) % N];
        ciphertext[n] = rnd ^ plaintext[n];
    }
    return 0;
}

void printRC4(char *input){
    for(size_t i = 0, len = strlen(input); i < len; i++)
        printf("%x", input[i]);
}

int RC4(char *plaintext, char *ciphertext) {
    KSA(S);
    PRGA(S, plaintext, ciphertext);
    return 0;
}

int main(int argc, char *argv[]) {
    char s1[] = "2885";
    char *input = s1;

    void *cptr = malloc(sizeof(int) * strlen(input));
    char *ciphertext = (char *)(cptr);

    void *cptrout = malloc(sizeof(int) * strlen(input));
    char *ciphertextout = (char *)(cptrout);

    RC4(input, ciphertext);
    printRC4(input);
    printf("        input\n");
    printRC4(ciphertext);
    printf("  ciphertext\n\n");

    RC4(ciphertext, ciphertextout);
    printRC4(ciphertext);
    printf("  input\n");
    printRC4(ciphertextout);
    printf("  deciphertext\n\n");

    printf("%d", strlen(input));

    return 0;
}