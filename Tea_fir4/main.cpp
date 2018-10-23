#include <iostream>
#include <chrono>
using namespace std::chrono;
class TeaEncryptor {
public:
    TeaEncryptor();
    void encrypt(uint32_t* v, uint32_t* k);
    void decrypt(uint32_t* v, uint32_t* k);
};

TeaEncryptor::TeaEncryptor(){}

void TeaEncryptor::encrypt(uint32_t* v, uint32_t* k) {
    uint32_t sum = 0, delta = 0x9e3779b9;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v[0] += ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        v[1] += ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
    }
}

void TeaEncryptor::decrypt(uint32_t* v, uint32_t* k) {
    uint32_t sum = 0xC6EF3720, delta = 0x9e3779b9;
    for (int i = 0; i<32; i++) {
        v[1] -= ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);;
        v[0] -= ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        sum -= delta;
    }
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    high_resolution_clock::time_point s;
    duration<double> diff;
    uint32_t N = 0;

    if(argc == 2)
        N = atoi(argv[1]); // escolha do tamanho do tiled
    else
        printf("Erro argumentos\n");

    // Cria TEA encryptor
    TeaEncryptor *encryptor = new TeaEncryptor();

    // Dados de entrada
    //uint32_t v[2] = { 0x9474B8E8, 0xC73BCA7D };
    uint32_t v[2] = { 0x2885842e, 0xa3e6999b };
    uint32_t k1 = 0x9474B8E8;
    uint32_t k2 = 0xC73BCA7D;
    uint32_t k3 = 0x53239142;
    uint32_t k4 = 0xf3c3121a;
    uint32_t k[4] = {k1, k2, k3, k4};

    s = high_resolution_clock::now();

    for (int i = 0; i < N; ++i) {
        uint32_t v0,v1;
        //printf("Input      IN0 0x%08llx IN1 0x%08llx \n", v[0], v[1]);
        //descritografa
        encryptor->decrypt(&v[0], &k[0]);
        v0 = v[0];
        v1 = v[1];
        //fir 4
        v[0] = v0 + v0 * 4 + v0 * 3 + v0 * 4;
        v[1] = v1 + v1 * 2 + v1 * 3 + v1 * 1;
        //criptografa
        encryptor->encrypt(&v[0], &k[0]);
        //printf("Crypto     OUT0 0x%08llx OUT1 0x%08llx \n", v[0], v[1]);
    }

    diff = high_resolution_clock::now() - s;

    printf("configuração: criptografa/descriptografa\nEntrada: %d\nTempo(s) %lf \n", N, diff.count());
    printf("end OUT0 0x%08llx OUT1 0x%08llx \n", v[0], v[1]);
    return 0;
}
