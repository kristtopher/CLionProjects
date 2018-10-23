#include <iostream>
#include <chrono>
#include <omp.h>
using namespace std::chrono;

class TeaEncryptor {
public:
    TeaEncryptor();
    void encrypt(uint32_t**v, uint32_t* k);
    void decrypt(uint32_t**v, uint32_t* k);
};

TeaEncryptor::TeaEncryptor(){}

void TeaEncryptor::encrypt(uint32_t**v, uint32_t* k) {
    int j = 0;
    #pragma omp parallel private(j)
    #pragma omp for schedule(static)
    for (j = 0; j < 4; j ++) {
        uint32_t v0 = v[j][0], v1 = v[j][1];
        uint32_t sum = 0;
        uint32_t delta = 0x9e3779b9;
        for (int i = 0; i < 32; i++) {
            sum += delta;
            v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
            v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        }
        v[j][0] = v0;
        v[j][1] = v1;
    }
}

void TeaEncryptor::decrypt(uint32_t**v, uint32_t* k) {
    int j = 0;
    #pragma omp parallel private(j)
    #pragma omp for schedule(static)
    for (j = 0; j < 4; j ++) {
        uint32_t v0 = v[j][0], v1 = v[j][1];
        uint32_t sum = 0xC6EF3720;
        uint32_t delta = 0x9e3779b9;
        for (int i = 0; i < 32; i++) {
            v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);;
            v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
            sum -= delta;
        }
        v[j][0] = v0;
        v[j][1] = v1;
    }
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    high_resolution_clock::time_point s;
    duration<double> diff;
    uint32_t N = 0;
    int mode = 0;

    if(argc == 3){
        mode = atoi(argv[1]);
        N = atoi(argv[2]) / 4; // escolha do tamanho do tiled
    }
    else
        printf("Erro argumentos\n");

    // Cria TEA encryptor
    TeaEncryptor *encryptor = new TeaEncryptor();

    // Dados de entrada

    uint32_t **v;
    v = (uint32_t **) malloc (4*sizeof(uint32_t *));
    for (int j = 0; j < 8; ++j) {
        v[j] = (uint32_t*) malloc (2*sizeof(uint32_t));
    }
    v[0][0] = 0x9474B8E8;
    v[0][1] = 0xC73BCA7D;
    v[1][0] = 0x9474B8E8;
    v[1][1] = 0xC73BCA7D;
    v[2][0] = 0x9474B8E8;
    v[2][1] = 0xC73BCA7D;
    v[3][0] = 0x9474B8E8;
    v[3][1] = 0xC73BCA7D;

//    for (int l = 0; l < 4; ++l) {
//        printf("V0 0x%08llx V1 0x%08llx\n", v[l][0], v[l][1]);
//    }

    uint32_t k1 = 0x9474B8E8;
    uint32_t k2 = 0xC73BCA7D;
    uint32_t k3 = 0x53239142;
    uint32_t k4 = 0xf3c3121a;
    uint32_t k[4] = {k1, k2, k3, k4};

    if(mode == 0) {
        s = high_resolution_clock::now();
        for (int i = 0; i <= N; ++i) {
            encryptor->encrypt(&v[0], &k[0]);
            v[0][0] = uint32_t(rand() % 4294967295);
            v[0][1] = uint32_t(rand() % 4294967295);
            v[1][0] = uint32_t(rand() % 4294967295);
            v[1][1] = uint32_t(rand() % 4294967295);
            v[2][0] = uint32_t(rand() % 4294967295);
            v[2][1] = uint32_t(rand() % 4294967295);
            v[3][0] = uint32_t(rand() % 4294967295);
            v[3][1] = uint32_t(rand() % 4294967295);
        }
        diff = high_resolution_clock::now() - s;
        printf("configuração: criptografa\nEntrada: %d\nTempo(s) %lf \n", N, diff.count());
    }
    if(mode == 1) {
        s = high_resolution_clock::now();
        for (int i = 0; i <= N; ++i) {
            //printf("I: %d\n",i);
            //printf("Input      IN0 0x%08llx IN1 0x%08llx    IN0 0x%08llx IN1 0x%08llx    IN0 0x%08llx IN1 0x%08llx     "
            //               "IN0 0x%08llx IN1 0x%08llx \n", v[0][0], v[0][1], v[1][0],v[1][1],v[2][0],v[2][1],v[3][0],v[3][1]);
            encryptor->encrypt(v, &k[0]);
            //printf("Crypto     IN0 0x%08llx IN1 0x%08llx    IN0 0x%08llx IN1 0x%08llx    IN0 0x%08llx IN1 0x%08llx     "
            //               "IN0 0x%08llx IN1 0x%08llx \n", v[0][0], v[0][1], v[1][0],v[1][1],v[2][0],v[2][1],v[3][0],v[3][1]);
            encryptor->decrypt(v, &k[0]);
            //printf("Decrypto   IN0 0x%08llx IN1 0x%08llx    IN0 0x%08llx IN1 0x%08llx    IN0 0x%08llx IN1 0x%08llx     "
            //               "IN0 0x%08llx IN1 0x%08llx \n\n\n", v[0][0], v[0][1], v[1][0],v[1][1],v[2][0],v[2][1],v[3][0],v[3][1]);
            v[0][0] = uint32_t(rand() % 4294967295);
            v[0][1] = uint32_t(rand() % 4294967295);
            v[1][0] = uint32_t(rand() % 4294967295);
            v[1][1] = uint32_t(rand() % 4294967295);
            v[2][0] = uint32_t(rand() % 4294967295);
            v[2][1] = uint32_t(rand() % 4294967295);
            v[3][0] = uint32_t(rand() % 4294967295);
            v[3][1] = uint32_t(rand() % 4294967295);
        }
        diff = high_resolution_clock::now() - s;
        printf("configuração: criptografa/descriptografa\nEntrada: %d\nTempo(s) %lf \n", N*4, diff.count());
    }

    return 0;
}