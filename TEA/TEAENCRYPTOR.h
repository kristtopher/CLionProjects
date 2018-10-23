//
// Created by kristtopher on 28/02/18.
//

#ifndef TEA_TEAENCRYPTOR_H
#define TEA_TEAENCRYPTOR_H
#include <stdint.h>
#include <iostream>

class TeaEncryptor {
public:
    TeaEncryptor();
    void encrypt(uint32_t* v, uint32_t* k);
    void decrypt(uint32_t* v, uint32_t* k);
};

#endif //TEA_TEAENCRYPTOR_H
