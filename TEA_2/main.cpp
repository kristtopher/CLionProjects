#include <iostream>
#include <chrono>
#include <omp.h>
#define DEBUG 0

using namespace std::chrono;

class TeaEncryptor {
public:
    TeaEncryptor();
    void encrypt(uint32_t *v0, uint32_t *v1, const uint32_t *k, int size);
    void decrypt(uint32_t *v0, uint32_t *v1, const uint32_t *k, int size);
    void initialData(uint32_t *v0, uint32_t *v1, int size);
    void fir(uint32_t *v0, uint32_t *k0, uint32_t *v1, uint32_t *k1, int size, int size_C);
    void print(uint32_t *v0, uint32_t *v1, int size);
};

TeaEncryptor::TeaEncryptor() = default;

void TeaEncryptor::initialData(uint32_t *v0, uint32_t *v1, int size) {
#pragma omp parallel num_threads(7)
    {
#pragma omp for
        for (int i = 0; i < size; i++) {
            //v0[i] = 0x2885842e;
            //v1[i] = 0xa3e6999b;
            v0[i] = rand() % 4294967295;
            v1[i] = rand() % 4294967295;
        }
    }
}

void TeaEncryptor::print(uint32_t *v0, uint32_t *v1, int size) {
//#pragma omp parallel num_threads(7)
//    {
//#pragma omp for
        for (int i = 0; i < size; i++)
            printf("IN0 0x%x IN1 0x%x \n", v0[i], v1[i]);
//    }
}

void TeaEncryptor::fir(uint32_t *v0, uint32_t *k0, uint32_t *v1, uint32_t *k1, int size, int size_C) {
#pragma omp parallel num_threads(7)
    {
#pragma omp for
        for (int i = 0; i < size; i++) {
            uint32_t temp0 = 0, temp1;
            int N_start_point = i - (size_C / 2);
            for (int j = 0; j < size_C; j++) {
                if (N_start_point + j >= 0 && N_start_point + j < size) {
                    temp0 += v0[N_start_point + j] * k0[j];
                    temp1 += v1[N_start_point + j] * k1[j];
                }
            }
            v0[i] = temp0;
            v1[i] = temp1;
        }
    }
}

void TeaEncryptor::encrypt(uint32_t *v0, uint32_t *v1, const uint32_t *k, int size) {
#pragma omp parallel num_threads(7)
    {
#pragma omp for
        for (int i = 0; i < size; i++) {
            uint32_t sum = 0, delta = 0x9e3779b9;
            for (int j = 0; j < 32; j++) {
                sum += delta;
                v0[i] += ((v1[i] << 4) + k[0]) ^ (v1[i] + sum) ^ ((v1[i] >> 5) + k[1]);
                v1[i] += ((v0[i] << 4) + k[2]) ^ (v0[i] + sum) ^ ((v0[i] >> 5) + k[3]);
            }
        }
    }
}

void TeaEncryptor::decrypt(uint32_t *v0, uint32_t *v1, const uint32_t *k, int size) {
#pragma omp parallel num_threads(7)
    {
#pragma omp for
        for (int i = 0; i < size; i++) {
            uint32_t sum = 0xC6EF3720, delta = 0x9e3779b9;
            for (int j = 0; j < 32; j++) {
                v1[i] -= ((v0[i] << 4) + k[2]) ^ (v0[i] + sum) ^ ((v0[i] >> 5) + k[3]);;
                v0[i] -= ((v1[i] << 4) + k[0]) ^ (v1[i] + sum) ^ ((v1[i] >> 5) + k[1]);
                sum -= delta;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    high_resolution_clock::time_point s;
    duration<double> diff;
    int N = 0; //Tamanho total de elementos
    int mode = 1;

    if (argc == 3) {
        mode = atoi(argv[1]);//configuraçao
        N = atoi(argv[2])/2;// numero de elementos pra cada fila
    } else {
        printf("Erro argumentos\n");
        return 0;
    }

    // Cria TEA encryptor
    TeaEncryptor *encryptor = new TeaEncryptor();

    uint32_t *v0, *v1;
    v0 = (uint32_t*)malloc(N * sizeof(uint32_t));
    v1 = (uint32_t*)malloc(N * sizeof(uint32_t));
    encryptor->initialData(v0,v1, N);

    uint32_t k[4] = {0x9474B8E8, 0xC73BCA7D, 0x53239142, 0xf3c3121a};
    uint32_t constant0[4] = {1,4,3,4};
    uint32_t constant1[4] = {1,2,3,1};
    if (mode == 0) {
        s = high_resolution_clock::now();
        encryptor->encrypt(v0,v1,k,N);
        //encryptor->decrypt(v0,v1,k,N);
        diff = high_resolution_clock::now() - s;
        if(DEBUG)
            encryptor->print(v0,v1,N);
        printf("Setup: Encrypt\nSize in0: %d\nSize in1: %d\nTime(s) %lf \n", N, N, diff.count());
    }
    if (mode == 1){
        s = high_resolution_clock::now();
        if(DEBUG){
            printf("Input:\n");
            encryptor->print(v0,v1,N);
        }

        encryptor->decrypt(v0,v1,k,N);
        if(DEBUG){
            printf("Decrypt:\n");
            encryptor->print(v0,v1,N);
        }

        encryptor->fir(v0,constant0,v1,constant1,N,4);
        if(DEBUG){
            printf("FIR4:\n");
            encryptor->print(v0,v1,N);
        }

        encryptor->encrypt(v0,v1, k, N);
        if(DEBUG){
            printf("Encrypt:\n");
            encryptor->print(v0,v1,N);
        }

        diff = high_resolution_clock::now() - s;
        //printf("Setup: Decrypt\nSize in0: %d\nSize in1: %d\nTime(s) %lf \n", N, N, diff.count());
        printf("Setup: AllConf \nSize in0: %d\nSize in1: %d\nTime(s) %lf \n", N, N, diff.count());
    }

    return 0;
}