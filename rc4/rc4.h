//
// Created by kristtopher on 30/05/18.
//

#ifndef RC4_RC4_H
#define RC4_RC4_H

#pragma once
#include <stdint.h>

// Rc4Context - This must be initialised using Rc4Initialised. Do not modify the contents of this structure directly.
typedef struct {
    uint32_t     i;
    uint32_t     j;
    uint8_t      S[256];
} Rc4Context;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4Initialise
//
//  Initialises an RC4 cipher and discards the specified number of first bytes.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Rc4Initialise(
                Rc4Context*     Context,        // [out]
                void const*     Key,            // [in]
                uint32_t        KeySize,        // [in]
                uint32_t        DropN           // [in]
        );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4Output
//
//  Outputs the requested number of bytes from the RC4 stream
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Rc4Output( Rc4Context*     Context,        // [in out]
                void*           Buffer,         // [out]
                uint32_t        Size            // [in]
        );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4Xor
//
//  XORs the RC4 stream with an input buffer and puts the results in an output buffer. This is used for encrypting
//  and decrypting data. InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
Rc4Xor(         Rc4Context*     Context,        // [in out]
                void const*     InBuffer,       // [in]
                void*           OutBuffer,      // [out]
                uint32_t        Size            // [in]
        );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Rc4XorWithKey
//
//  This function combines Rc4Initialise and Rc4Xor. This is suitable when encrypting/decrypting data in one go with a
//  key that is not going to be reused.
//  InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
Rc4XorWithKey(  uint8_t const*      Key,                    // [in]
                uint32_t            KeySize,                // [in]
                uint32_t            DropN,                  // [in]
                void const*         InBuffer,               // [in]
                void*               OutBuffer,              // [out]
                uint32_t            BufferSize              // [in]
        );


#endif //RC4_RC4_H
