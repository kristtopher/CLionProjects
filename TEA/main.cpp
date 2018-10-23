#include "TEAENCRYPTOR.h"

int main() {
    srand(time(NULL));

    // Cria TEA encryptor
    TeaEncryptor *encryptor = new TeaEncryptor();

    // Dados de entrada
    uint32_t v[2] = { 0x9474B8E8, 0xC73BCA7D };

    uint32_t k1 = 0x9474B8E8;
    uint32_t k2 = 0xC73BCA7D;
    uint32_t k3 = 0x53239142;
    uint32_t k4 = 0xf3c3121a;
    uint32_t k[4] = {k1, k2, k3, k4};

    uint32_t t0[5];
    uint32_t t1[5];
    printf("Input   IN0 0x%08llx IN1 0x%08llx \n", v[0], v[1]);
    encryptor->encrypt(&v[0], &k[0]);
    printf("Encrypt IN0 0x%08llx IN1 0x%08llx \n\n", v[0], v[1]);
    printf("Input   IN0 0x%08llx IN1 0x%08llx\n", v[0], v[1]);
    encryptor->decrypt(&v[0], &k[0]);
    printf("Decrypt IN0 0x%08llx IN1 0x%08llx \n\n", v[0], v[1]);

//    for (int i = 0; i <= 4; ++i) {
//        // Confirma dados de entrada
//        printf("Input   IN0 0x%08llx IN1 0x%08llx \n", v[0], v[1]);
//
//        // Criptografa valores
//        encryptor->encrypt(&v[0], &k[0]);
//
//        // Resultados criptografia
//        printf("Encrypt IN0 0x%08llx IN1 0x%08llx \n\n", v[0], v[1]);
//
//        t0[i] = v[0];
//        t1[i] = v[1];
//
//        v[0] = rand() % 4294967295;
//        v[1] = rand() % 4294967295;
//    }
//
//    for (int j = 4; j >=0; --j) {
//        v[0]= t0[j];
//        v[1]= t1[j];
//
//        // Confirma dados de entrada
//        printf("Input   IN0 0x%08llx IN1 0x%08llx\n", v[0], v[1]);
//
//        // Descriptografa valores
//        encryptor->decrypt(&v[0], &k[0]);
//
//        // Resultados descriptografia
//        printf("Decrypt IN0 0x%08llx IN1 0x%08llx \n\n", v[0], v[1]);
//
//    }
    return 0;
}