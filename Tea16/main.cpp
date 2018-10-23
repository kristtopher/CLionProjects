#include <iostream>
#include <chrono>
#define DEBUG 1

using namespace std::chrono;

class TeaEncryptor {
public:
    TeaEncryptor();
    void encrypt16(uint16_t *v0, uint16_t *v1, const uint16_t *k, int size);
    void decrypt16(uint16_t *v0, uint16_t *v1, const uint16_t *k, int size);
    void initialData16(uint16_t *v0, uint16_t *v1, int size);
    void print16(uint16_t *v0, uint16_t *v1, int size);
};

TeaEncryptor::TeaEncryptor() = default;

void TeaEncryptor::initialData16(uint16_t *v0, uint16_t *v1, int size) {
    for (int i = 0; i < size; i++) {
        //v0[i] = rand() % 65535;
        //v1[i] = rand() % 65535;
        v0[i] = 0xfee;
        v1[i] = 0xfee;
        //v0[i] = 0x3AA6;
        //v1[i] = 0x678B;
    }
}

void TeaEncryptor::print16(uint16_t *v0, uint16_t *v1, int size) {
    for (int i = 0; i < size; i ++)
        printf("IN0 0x%x IN1 0x%x \n", v0[i], v1[i]);
}

void TeaEncryptor::encrypt16(uint16_t *v0, uint16_t *v1, const uint16_t *k, int size) {
    for (int i = 0; i < size; i ++) {
        uint16_t sum = 0, delta = 0x2C3; //547 primo
        for (int j = 0; j < 32; j++) {
            sum   += delta;
            v0[i] += ((v1[i] << 4) + k[0]) ^ (v1[i] + sum) ^ ((v1[i] >> 5) + k[1]);// << 4   >> 5
            v1[i] += ((v0[i] << 4) + k[2]) ^ (v0[i] + sum) ^ ((v0[i] >> 5) + k[3]);
        }
    }
}

void TeaEncryptor::decrypt16(uint16_t *v0, uint16_t *v1, const uint16_t *k, int size) {
    for (int i = 0; i < size; i ++) {
        uint16_t sum = 0x5860, delta = 0x2C3;
        for (int j = 0; j < 32; j++) {
            v1[i] -= ((v0[i] << 4) + k[2]) ^ (v0[i] + sum) ^ ((v0[i] >> 5) + k[3]);;
            v0[i] -= ((v1[i] << 4) + k[0]) ^ (v1[i] + sum) ^ ((v1[i] >> 5) + k[1]);
            sum   -= delta;
        }
    }
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    high_resolution_clock::time_point s;
    duration<double> diff;
    int N = 0;
    int mode = 0;

    if (argc == 3) {
        mode = atoi(argv[1]);
        N = atoi(argv[2])/2;
    } else
        printf("Erro argumentos\n");

    // Cria TEA encryptor
    TeaEncryptor *encryptor = new TeaEncryptor();

    uint16_t *v0, *v1;
    v0 = (uint16_t *)malloc(N * sizeof(uint16_t ));
    v1 = (uint16_t *)malloc(N * sizeof(uint16_t ));
    encryptor->initialData16(v0,v1, N);

    uint16_t  k[4] = {0x5B60, 0x1D6A, 0x4A62, 0x5463};

    if (mode == 0) {
        if(DEBUG){
            printf("Input:\n");
            encryptor->print16(v0,v1,N);
        }

        s = high_resolution_clock::now();
        encryptor->encrypt16(v0,v1,k,N);
        diff = high_resolution_clock::now() - s;

        if(DEBUG)
            encryptor->print16(v0,v1,N);
        printf("Setup: Encrypt\nSize in0: %d\nSize in1: %d\nTime(s) %lf \n", N, N, diff.count());
    }
    if (mode == 1){
        s = high_resolution_clock::now();
        if(DEBUG){
            printf("Input:\n");
            encryptor->print16(v0,v1,N);
        }

        encryptor->decrypt16(v0,v1,k,N);

        if(DEBUG){
            printf("Decrypt:\n");
            encryptor->print16(v0,v1,N);
        }

        encryptor->encrypt16(v0,v1, k, N);

        if(DEBUG){
            printf("Encrypt:\n");
            encryptor->print16(v0,v1,N);
        }

        diff = high_resolution_clock::now() - s;
        printf("Setup: Decrypt/Encrypt\nSize in0: %d\nSize in1: %d\nTime(s) %lf \n", N, N, diff.count());
    }
    return 0;
}