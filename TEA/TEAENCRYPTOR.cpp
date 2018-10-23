//
// Created by kristtopher on 28/02/18.
//

#include "TEAENCRYPTOR.h"

TeaEncryptor::TeaEncryptor(){}

void TeaEncryptor::encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    uint32_t delta = 0x9e3779b9;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0;
    v[1] = v1;
}


void TeaEncryptor::decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720;
    uint32_t delta = 0x9e3779b9;
    for (int i = 0; i<32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}