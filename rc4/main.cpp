////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "rc4.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  DEFINITIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __min
#define __min( x, y )  (((x) < (y))?(x):(y))
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  CONSTANTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define BUFFER_SIZE             1024

int main(int ArgC, char** ArgV) {
    char*           string;
    uint32_t        numBytes;
    uint32_t        i;
    uint8_t         buffer [BUFFER_SIZE];
    uint32_t        amountLeft;
    uint32_t        chunk;
    Rc4Context      rc4 = {0};
    uint32_t        dropN = 0;

    if( 3 != ArgC  &&  4 != ArgC ) {
        printf("Syntax\nRc4Output <Key> <NumBytes> [DropN]\n" );
        return 1;
    }

    string = ArgV[1];
    numBytes = atoi( ArgV[2] );
    if( 4 == ArgC )
        dropN = atoi( ArgV[3] );

    Rc4Initialise( &rc4, string, (uint32_t)strlen(string), dropN );

    amountLeft = numBytes;
    while( amountLeft > 0 ) {
        chunk = __min( amountLeft, BUFFER_SIZE );
        Rc4Output( &rc4, buffer, chunk );
        amountLeft -= chunk;

        for( i=0; i<chunk; i++ )
            printf( "%2.2x", buffer[i] );
    }

    printf( "\n" );

    return 0;
}